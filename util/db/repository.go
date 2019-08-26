package db

import (
	"fmt"
	"hash/fnv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apiv1 "k8s.io/api/core/v1"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-cd/common"
	appsv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/util/git"
	"github.com/argoproj/argo-cd/util/settings"
)

const (
	// The name of the key storing the username in the secret
	username = "username"
	// The name of the key storing the password in the secret
	password = "password"
	// The name of the key storing the SSH private in the secret
	sshPrivateKey = "sshPrivateKey"
	// The name of the key storing the TLS client cert data in the secret
	tlsClientCertData = "tlsClientCertData"
	// The name of the key storing the TLS client cert key in the secret
	tlsClientCertKey = "tlsClientCertKey"
)

// ListRepoURLs returns list of repositories
func (db *db) ListRepoURLs(ctx context.Context) ([]string, error) {
	repos, err := db.settingsMgr.GetRepositories()
	if err != nil {
		return nil, err
	}

	urls := make([]string, len(repos))
	for i := range repos {
		urls[i] = repos[i].URL
	}
	return urls, nil
}

// CreateRepository creates a repository
func (db *db) CreateRepository(ctx context.Context, r *appsv1.Repository) (*appsv1.Repository, error) {
	repos, err := db.settingsMgr.GetRepositories()
	if err != nil {
		return nil, err
	}

	index := getRepositoryIndex(repos, r.Repo)
	if index > -1 {
		return nil, status.Errorf(codes.AlreadyExists, "repository '%s' already exists", r.Repo)
	}

	data := make(map[string][]byte)
	if r.Username != "" {
		data[username] = []byte(r.Username)
	}
	if r.Password != "" {
		data[password] = []byte(r.Password)
	}
	if r.SSHPrivateKey != "" {
		data[sshPrivateKey] = []byte(r.SSHPrivateKey)
	}

	repoInfo := settings.RepoCredentials{
		URL:                   r.Repo,
		InsecureIgnoreHostKey: r.IsInsecure(),
		Insecure:              r.IsInsecure(),
		EnableLFS:             r.EnableLFS,
	}
	err = db.updateSecrets(&repoInfo, r)
	if err != nil {
		return nil, err
	}

	repos = append(repos, repoInfo)
	err = db.settingsMgr.SaveRepositories(repos)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// GetRepository returns a repository by URL. If the repository doesn't have any
// credentials attached to it, checks if a credential set for the repo's URL is
// configured and copies them to the returned repository data.
func (db *db) GetRepository(ctx context.Context, repoURL string) (*appsv1.Repository, error) {
	repos, err := db.settingsMgr.GetRepositories()
	if err != nil {
		return nil, err
	}

	repo := &appsv1.Repository{Repo: repoURL}
	index := getRepositoryIndex(repos, repoURL)
	if index >= 0 {
		repo, err = db.credentialsToRepository(repos[index])
		if err != nil {
			return nil, err
		}
	}

	// Check for and copy repository credentials, if repo has none configured.
	if !repo.HasCredentials() {
		creds, err := db.GetRepositoryCredentials(ctx, repoURL)
		if err == nil {
			if creds != nil {
				log.WithFields(log.Fields{"repoURL": repo.Repo, "credUrl": creds.Repo}).Info("copying credentials")
				repo.CopyCredentialsFrom(creds)
				repo.InheritedCreds = true
			}
		} else {
			return nil, err
		}
	}

	return repo, err
}

// UpdateRepository updates a repository
func (db *db) UpdateRepository(ctx context.Context, r *appsv1.Repository) (*appsv1.Repository, error) {
	repos, err := db.settingsMgr.GetRepositories()
	if err != nil {
		return nil, err
	}

	index := getRepositoryIndex(repos, r.Repo)
	if index < 0 {
		return nil, status.Errorf(codes.NotFound, "repo '%s' not found", r.Repo)
	}

	repoInfo := repos[index]
	err = db.updateSecrets(&repoInfo, r)
	if err != nil {
		return nil, err
	}

	// Update boolean settings
	repoInfo.InsecureIgnoreHostKey = r.IsInsecure()
	repoInfo.Insecure = r.IsInsecure()
	repoInfo.EnableLFS = r.EnableLFS

	repos[index] = repoInfo
	err = db.settingsMgr.SaveRepositories(repos)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Delete updates a repository
func (db *db) DeleteRepository(ctx context.Context, repoURL string) error {
	repos, err := db.settingsMgr.GetRepositories()
	if err != nil {
		return err
	}

	index := getRepositoryIndex(repos, repoURL)
	if index < 0 {
		return status.Errorf(codes.NotFound, "repo '%s' not found", repoURL)
	}
	err = db.updateSecrets(&repos[index], &appsv1.Repository{
		SSHPrivateKey:     "",
		Password:          "",
		Username:          "",
		TLSClientCertData: "",
		TLSClientCertKey:  "",
	})
	if err != nil {
		return err
	}
	repos = append(repos[:index], repos[index+1:]...)
	return db.settingsMgr.SaveRepositories(repos)
}

// ListRepositoryCredentials returns a list of URLs that contain repo credential sets
func (db *db) ListRepositoryCredentials(ctx context.Context) ([]string, error) {
	repos, err := db.settingsMgr.GetRepositoryCredentials()
	if err != nil {
		return nil, err
	}

	urls := make([]string, len(repos))
	for i := range repos {
		urls[i] = repos[i].URL
	}

	return urls, nil
}

// GetRepositoryCredentials retrieves a repository credential set
func (db *db) GetRepositoryCredentials(ctx context.Context, repoURL string) (*appsv1.Repository, error) {
	var credential *appsv1.Repository

	repoCredentials, err := db.settingsMgr.GetRepositoryCredentials()
	if err != nil {
		return nil, err
	}
	index := getRepositoryCredentialIndex(repoCredentials, repoURL)
	if index >= 0 {
		credential, err = db.credentialsToRepository(repoCredentials[index])
		if err != nil {
			return nil, err
		}
	}

	return credential, err
}

// CreateRepositoryCredentials creates a repository credential set
func (db *db) CreateRepositoryCredentials(ctx context.Context, r *appsv1.Repository) (*appsv1.Repository, error) {
	repos, err := db.settingsMgr.GetRepositoryCredentials()
	if err != nil {
		return nil, err
	}

	index := getRepositoryIndex(repos, r.Repo)
	if index > -1 {
		return nil, status.Errorf(codes.AlreadyExists, "repository credentials for '%s' already exists", r.Repo)
	}

	data := make(map[string][]byte)
	if r.Username != "" {
		data[username] = []byte(r.Username)
	}
	if r.Password != "" {
		data[password] = []byte(r.Password)
	}
	if r.SSHPrivateKey != "" {
		data[sshPrivateKey] = []byte(r.SSHPrivateKey)
	}

	repoInfo := settings.RepoCredentials{
		URL: r.Repo,
	}

	err = db.updateSecrets(&repoInfo, r)
	if err != nil {
		return nil, err
	}

	repos = append(repos, repoInfo)
	err = db.settingsMgr.SaveRepositoryCredentials(repos)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// UpdateRepositoryCredentials updates a repository credential set
func (db *db) UpdateRepositoryCredentials(ctx context.Context, r *appsv1.Repository) (*appsv1.Repository, error) {
	repos, err := db.settingsMgr.GetRepositoryCredentials()
	if err != nil {
		return nil, err
	}

	index := getRepositoryCredentialIndex(repos, r.Repo)
	if index < 0 {
		return nil, status.Errorf(codes.NotFound, "repository credentials '%s' not found", r.Repo)
	}

	repoInfo := repos[index]
	err = db.updateSecrets(&repoInfo, r)
	if err != nil {
		return nil, err
	}

	repos[index] = repoInfo
	err = db.settingsMgr.SaveRepositoryCredentials(repos)
	if err != nil {
		return nil, err
	}
	return r, nil

}

// DeleteRepositoryCredentials deletes a repository credential set from config, and
// also all the secrets which actually contained the credentials.
func (db *db) DeleteRepositoryCredentials(ctx context.Context, name string) error {
	repos, err := db.settingsMgr.GetRepositoryCredentials()
	if err != nil {
		return err
	}

	index := getRepositoryCredentialIndex(repos, name)
	if index < 0 {
		return status.Errorf(codes.NotFound, "repository credentials '%s' not found", name)
	}
	err = db.updateSecrets(&repos[index], &appsv1.Repository{
		SSHPrivateKey:     "",
		Password:          "",
		Username:          "",
		TLSClientCertData: "",
		TLSClientCertKey:  "",
	})
	if err != nil {
		return err
	}
	repos = append(repos[:index], repos[index+1:]...)
	return db.settingsMgr.SaveRepositoryCredentials(repos)
}

func (db *db) credentialsToRepository(repoInfo settings.RepoCredentials) (*appsv1.Repository, error) {
	repo := &appsv1.Repository{
		Repo:                  repoInfo.URL,
		InsecureIgnoreHostKey: repoInfo.InsecureIgnoreHostKey,
		Insecure:              repoInfo.Insecure,
		EnableLFS:             repoInfo.EnableLFS,
	}
	err := db.unmarshalFromSecretsStr(map[*string]*apiv1.SecretKeySelector{
		&repo.Username:          repoInfo.UsernameSecret,
		&repo.Password:          repoInfo.PasswordSecret,
		&repo.SSHPrivateKey:     repoInfo.SSHPrivateKeySecret,
		&repo.TLSClientCertData: repoInfo.TLSClientCertDataSecret,
		&repo.TLSClientCertKey:  repoInfo.TLSClientCertKeySecret,
	}, make(map[string]*apiv1.Secret))

	return repo, err
}

func (db *db) updateSecrets(repoInfo *settings.RepoCredentials, r *appsv1.Repository) error {
	secretsData := make(map[string]map[string][]byte)

	setSecretData := func(secretKey *apiv1.SecretKeySelector, value string, defaultKeyName string) *apiv1.SecretKeySelector {
		if secretKey == nil && value != "" {
			secretKey = &apiv1.SecretKeySelector{
				LocalObjectReference: apiv1.LocalObjectReference{Name: repoURLToSecretName(r.Repo)},
				Key:                  defaultKeyName,
			}
		}

		if secretKey != nil {
			data, ok := secretsData[secretKey.Name]
			if !ok {
				data = map[string][]byte{}
			}
			if value != "" {
				data[secretKey.Key] = []byte(value)
			}
			secretsData[secretKey.Name] = data
		}

		if value == "" {
			secretKey = nil
		}

		return secretKey
	}

	repoInfo.UsernameSecret = setSecretData(repoInfo.UsernameSecret, r.Username, username)
	repoInfo.PasswordSecret = setSecretData(repoInfo.PasswordSecret, r.Password, password)
	repoInfo.SSHPrivateKeySecret = setSecretData(repoInfo.SSHPrivateKeySecret, r.SSHPrivateKey, sshPrivateKey)
	repoInfo.TLSClientCertDataSecret = setSecretData(repoInfo.TLSClientCertDataSecret, r.TLSClientCertData, tlsClientCertData)
	repoInfo.TLSClientCertKeySecret = setSecretData(repoInfo.TLSClientCertKeySecret, r.TLSClientCertKey, tlsClientCertKey)
	for k, v := range secretsData {
		err := db.upsertSecret(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *db) upsertSecret(name string, data map[string][]byte) error {
	secret, err := db.kubeclientset.CoreV1().Secrets(db.ns).Get(name, metav1.GetOptions{})
	if err != nil {
		if apierr.IsNotFound(err) {
			if len(data) == 0 {
				return nil
			}
			_, err = db.kubeclientset.CoreV1().Secrets(db.ns).Create(&apiv1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
					Annotations: map[string]string{
						common.AnnotationKeyManagedBy: common.AnnotationValueManagedByArgoCD,
					},
				},
				Data: data,
			})
			if err != nil {
				return err
			}
		}
	} else {
		for _, key := range []string{username, password, sshPrivateKey, tlsClientCertData, tlsClientCertKey} {
			if secret.Data == nil {
				secret.Data = make(map[string][]byte)
			}
			if val, ok := data[key]; ok && len(val) > 0 {
				secret.Data[key] = val
			} else {
				delete(secret.Data, key)
			}
		}
		if len(secret.Data) == 0 {
			isManagedByArgo := (secret.Annotations != nil && secret.Annotations[common.AnnotationKeyManagedBy] == common.AnnotationValueManagedByArgoCD) ||
				(secret.Labels != nil && secret.Labels[common.LabelKeySecretType] == "repository")
			if isManagedByArgo {
				return db.kubeclientset.CoreV1().Secrets(db.ns).Delete(name, &metav1.DeleteOptions{})
			}
			return nil
		} else {
			_, err = db.kubeclientset.CoreV1().Secrets(db.ns).Update(secret)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getRepositoryIndex(repos []settings.RepoCredentials, repoURL string) int {
	for i, repo := range repos {
		if git.SameURL(repo.URL, repoURL) {
			return i
		}
	}
	return -1
}

// getRepositoryCredentialIndex returns the index of the best matching repository credential
// configuration, i.e. the one with the longest match
func getRepositoryCredentialIndex(repoCredentials []settings.RepoCredentials, repoURL string) int {
	var max, idx int = 0, -1
	repoURL = git.NormalizeGitURL(repoURL)
	for i, cred := range repoCredentials {
		credUrl := git.NormalizeGitURL(cred.URL)
		if strings.HasPrefix(repoURL, credUrl) {
			if len(credUrl) > max {
				max = len(credUrl)
				idx = i
			}
		}
	}
	return idx
}

// repoURLToSecretName hashes repo URL to a secret name using a formula. This is used when
// repositories are _imperatively_ created and need its credentials to be stored in a secret.
// NOTE: this formula should not be considered stable and may change in future releases.
// Do NOT rely on this formula as a means of secret lookup, only secret creation.
func repoURLToSecretName(repo string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(repo))
	// Part of the original repo name is incorporated into the secret name for debugging purposes
	parts := strings.Split(strings.TrimSuffix(repo, ".git"), "/")
	shortName := strings.ToLower(strings.Replace(parts[len(parts)-1], "_", "-", -1))
	return fmt.Sprintf("repo-%s-%v", shortName, h.Sum32())
}
