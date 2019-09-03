package account

import (
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/argoproj/argo-cd/common"
	"github.com/argoproj/argo-cd/pkg/apiclient/account"
	"github.com/argoproj/argo-cd/util/password"
	"github.com/argoproj/argo-cd/util/session"
	"github.com/argoproj/argo-cd/util/settings"
)

// Server provides a Session service
type Server struct {
	sessionMgr  *session.SessionManager
	settingsMgr *settings.SettingsManager
}

// NewServer returns a new instance of the Session service
func NewServer(sessionMgr *session.SessionManager, settingsMgr *settings.SettingsManager) *Server {
	return &Server{
		sessionMgr:  sessionMgr,
		settingsMgr: settingsMgr,
	}

}

// UpdatePassword updates the password of the local admin superuser.
func (s *Server) UpdatePassword(ctx context.Context, q *account.UpdatePasswordRequest) (*account.UpdatePasswordResponse, error) {
	username := session.Sub(ctx)
	if username != common.ArgoCDAdminUsername {
		return nil, status.Errorf(codes.InvalidArgument, "password can only be changed for local users, not user %q", username)
	}

	cdSettings, err := s.settingsMgr.GetSettings()
	if err != nil {
		return nil, err
	}

	err = s.sessionMgr.VerifyUsernamePassword(username, q.CurrentPassword)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "current password does not match")
	}

	hashedPassword, err := password.HashPassword(q.NewPassword)
	if err != nil {
		return nil, err
	}

	cdSettings.AdminPasswordHash = hashedPassword
	cdSettings.AdminPasswordMtime = time.Now().UTC()

	err = s.settingsMgr.SaveSettings(cdSettings)
	if err != nil {
		return nil, err
	}
	log.Infof("user '%s' updated password", username)
	return &account.UpdatePasswordResponse{}, nil

}

func (s *Server) GetUserInfo(ctx context.Context, q *account.GetUserInfoRequest) (*account.GetUserInfoResponse, error) {
	return &account.GetUserInfoResponse{LoggedIn: session.LoggedIn(ctx), Username: session.Username(ctx), Groups: session.Groups(ctx)}, nil
}
