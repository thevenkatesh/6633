package repository

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"reflect"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	appsv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/reposerver"
	"github.com/argoproj/argo-cd/reposerver/repository"
	"github.com/argoproj/argo-cd/server/rbacpolicy"
	"github.com/argoproj/argo-cd/util"
	"github.com/argoproj/argo-cd/util/cache"
	"github.com/argoproj/argo-cd/util/db"
	"github.com/argoproj/argo-cd/util/git"
	"github.com/argoproj/argo-cd/util/kustomize"
	"github.com/argoproj/argo-cd/util/rbac"
)

// Server provides a Repository service
type Server struct {
	db            db.ArgoDB
	repoClientset reposerver.Clientset
	enf           *rbac.Enforcer
	cache         *cache.Cache
}

// NewServer returns a new instance of the Repository service
func NewServer(
	repoClientset reposerver.Clientset,
	db db.ArgoDB,
	enf *rbac.Enforcer,
	cache *cache.Cache,
) *Server {
	return &Server{
		db:            db,
		repoClientset: repoClientset,
		enf:           enf,
		cache:         cache,
	}
}

func (s *Server) getConnectionState(ctx context.Context, url string) appsv1.ConnectionState {
	if connectionState, err := s.cache.GetRepoConnectionState(url); err == nil {
		return connectionState
	}
	now := metav1.Now()
	connectionState := appsv1.ConnectionState{
		Status:     appsv1.ConnectionStatusSuccessful,
		ModifiedAt: &now,
	}
	repo, err := s.db.GetRepository(ctx, url)

	if err == nil {
		err = git.TestRepo(repo.Repo, repo.Username, repo.Password, repo.SSHPrivateKey, repo.InsecureIgnoreHostKey)
	}
	if err != nil {
		connectionState.Status = appsv1.ConnectionStatusFailed
		connectionState.Message = fmt.Sprintf("Unable to connect to repository: %v", err)
	}
	err = s.cache.SetRepoConnectionState(url, &connectionState)
	if err != nil {
		log.Warnf("getConnectionState cache set error %s: %v", url, err)
	}
	return connectionState
}

// List returns list of repositories
func (s *Server) List(ctx context.Context, q *RepoQuery) (*appsv1.RepositoryList, error) {
	urls, err := s.db.ListRepoURLs(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]appsv1.Repository, 0)
	for _, url := range urls {
		if s.enf.Enforce(ctx.Value("claims"), rbacpolicy.ResourceRepositories, rbacpolicy.ActionGet, url) {
			items = append(items, appsv1.Repository{Repo: url})
		}
	}
	err = util.RunAllAsync(len(items), func(i int) error {
		items[i].ConnectionState = s.getConnectionState(ctx, items[i].Repo)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &appsv1.RepositoryList{Items: items}, nil
}

func (s *Server) listAppsPaths(
	ctx context.Context, repoClient repository.RepoServerServiceClient, repo *appsv1.Repository, revision string, subPath string) (map[string]appsv1.ApplicationSourceType, error) {

	if revision == "" {
		revision = "HEAD"
	}

	ksonnetRes, err := repoClient.ListDir(ctx, &repository.ListDirRequest{Repo: repo, Revision: revision, Path: path.Join(subPath, "*app.yaml")})
	if err != nil {
		return nil, err
	}
	componentRes, err := repoClient.ListDir(ctx, &repository.ListDirRequest{Repo: repo, Revision: revision, Path: path.Join(subPath, "*components/params.libsonnet")})
	if err != nil {
		return nil, err
	}

	helmRes, err := repoClient.ListDir(ctx, &repository.ListDirRequest{Repo: repo, Revision: revision, Path: path.Join(subPath, "*Chart.yaml")})
	if err != nil {
		return nil, err
	}

	kustomizationRes, err := getKustomizationRes(ctx, repoClient, repo, revision, subPath)
	if err != nil {
		return nil, err
	}

	componentDirs := make(map[string]interface{})
	for _, i := range componentRes.Items {
		d := filepath.Dir(filepath.Dir(i))
		componentDirs[d] = struct{}{}
	}

	pathToType := make(map[string]appsv1.ApplicationSourceType)
	for _, i := range ksonnetRes.Items {
		d := filepath.Dir(i)
		if _, ok := componentDirs[d]; ok {
			pathToType[i] = appsv1.ApplicationSourceTypeKsonnet
		}
	}

	for i := range helmRes.Items {
		pathToType[helmRes.Items[i]] = appsv1.ApplicationSourceTypeHelm
	}

	for i := range kustomizationRes.Items {
		pathToType[kustomizationRes.Items[i]] = appsv1.ApplicationSourceTypeKustomize
	}
	return pathToType, nil
}

func getKustomizationRes(ctx context.Context, repoClient repository.RepoServerServiceClient, repo *appsv1.Repository, revision string, subPath string) (*repository.FileList, error) {
	for _, kustomization := range kustomize.KustomizationNames {
		request := repository.ListDirRequest{Repo: repo, Revision: revision, Path: path.Join(subPath, "*"+kustomization)}
		kustomizationRes, err := repoClient.ListDir(ctx, &request)
		if err != nil {
			return nil, err
		} else {
			return kustomizationRes, nil
		}
	}
	return nil, errors.New("could not find kustomization")
}

// ListApps returns list of apps in the repo
func (s *Server) ListApps(ctx context.Context, q *RepoAppsQuery) (*RepoAppsResponse, error) {
	if err := s.enf.EnforceErr(ctx.Value("claims"), rbacpolicy.ResourceRepositories, rbacpolicy.ActionGet, q.Repo); err != nil {
		return nil, err
	}
	repo, err := s.db.GetRepository(ctx, q.Repo)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Code() == codes.NotFound {
			repo = &appsv1.Repository{
				Repo: q.Repo,
			}
		} else {
			return nil, err
		}
	}

	// Test the repo
	conn, repoClient, err := s.repoClientset.NewRepoServerClient()
	if err != nil {
		return nil, err
	}
	defer util.Close(conn)

	revision := q.Revision
	if revision == "" {
		revision = "HEAD"
	}

	paths, err := s.listAppsPaths(ctx, repoClient, repo, revision, "")
	if err != nil {
		return nil, err
	}
	items := make([]*AppInfo, 0)
	for appFilePath, appType := range paths {
		items = append(items, &AppInfo{Path: path.Dir(appFilePath), Type: string(appType)})
	}
	return &RepoAppsResponse{Items: items}, nil
}

func (s *Server) GetAppDetails(ctx context.Context, q *RepoAppDetailsQuery) (*repository.RepoAppDetailsResponse, error) {
	if err := s.enf.EnforceErr(ctx.Value("claims"), rbacpolicy.ResourceRepositories, rbacpolicy.ActionGet, q.Repo); err != nil {
		return nil, err
	}
	repo, err := s.db.GetRepository(ctx, q.Repo)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Code() == codes.NotFound {
			repo = &appsv1.Repository{
				Repo: q.Repo,
			}
		} else {
			return nil, err
		}
	}

	conn, repoClient, err := s.repoClientset.NewRepoServerClient()
	if err != nil {
		return nil, err
	}
	defer util.Close(conn)
	helmRepos, err := s.db.ListHelmRepos(ctx)
	if err != nil {
		return nil, err
	}
	return repoClient.GetAppDetails(ctx, &repository.RepoServerAppDetailsQuery{
		Repo:      repo,
		Revision:  q.Revision,
		Path:      q.Path,
		HelmRepos: helmRepos,
		Helm:      q.Helm,
		Ksonnet:   q.Ksonnet,
	})
}

// Create creates a repository
func (s *Server) Create(ctx context.Context, q *RepoCreateRequest) (*appsv1.Repository, error) {
	if err := s.enf.EnforceErr(ctx.Value("claims"), rbacpolicy.ResourceRepositories, rbacpolicy.ActionCreate, q.Repo.Repo); err != nil {
		return nil, err
	}
	r := q.Repo
	err := git.TestRepo(r.Repo, r.Username, r.Password, r.SSHPrivateKey, r.InsecureIgnoreHostKey)
	if err != nil {
		return nil, err
	}

	r.ConnectionState = appsv1.ConnectionState{Status: appsv1.ConnectionStatusSuccessful}
	repo, err := s.db.CreateRepository(ctx, r)
	if status.Convert(err).Code() == codes.AlreadyExists {
		// act idempotent if existing spec matches new spec
		existing, getErr := s.db.GetRepository(ctx, r.Repo)
		if getErr != nil {
			return nil, status.Errorf(codes.Internal, "unable to check existing repository details: %v", getErr)
		}

		// repository ConnectionState may differ, so make consistent before testing
		existing.ConnectionState = r.ConnectionState
		if reflect.DeepEqual(existing, r) {
			repo, err = existing, nil
		} else if q.Upsert {
			return s.Update(ctx, &RepoUpdateRequest{Repo: r})
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "existing repository spec is different; use upsert flag to force update")
		}
	}
	return &appsv1.Repository{Repo: repo.Repo}, err
}

// Update updates a repository
func (s *Server) Update(ctx context.Context, q *RepoUpdateRequest) (*appsv1.Repository, error) {
	if err := s.enf.EnforceErr(ctx.Value("claims"), rbacpolicy.ResourceRepositories, rbacpolicy.ActionUpdate, q.Repo.Repo); err != nil {
		return nil, err
	}
	_, err := s.db.UpdateRepository(ctx, q.Repo)
	return &appsv1.Repository{Repo: q.Repo.Repo}, err
}

// Delete updates a repository
func (s *Server) Delete(ctx context.Context, q *RepoQuery) (*RepoResponse, error) {
	if err := s.enf.EnforceErr(ctx.Value("claims"), rbacpolicy.ResourceRepositories, rbacpolicy.ActionDelete, q.Repo); err != nil {
		return nil, err
	}

	// invalidate cache
	if err := s.cache.SetRepoConnectionState(q.Repo, nil); err == nil {
		log.Errorf("error invalidating cache: %v", err)
	}

	err := s.db.DeleteRepository(ctx, q.Repo)
	return &RepoResponse{}, err
}
