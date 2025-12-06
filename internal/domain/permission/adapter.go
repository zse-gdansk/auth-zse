package permission

import (
	svc "github.com/Anvoria/authly/internal/domain/service"
)

// NewServiceRepositoryAdapter creates an adapter from service.Repository to ServiceRepository
func NewServiceRepositoryAdapter(repo svc.Repository) ServiceRepository {
	return &serviceRepositoryAdapter{repo: repo}
}

type serviceRepositoryAdapter struct {
	repo svc.Repository
}

func (a *serviceRepositoryAdapter) FindByID(id string) (*ServiceModel, error) {
	svc, err := a.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	return &ServiceModel{
		ID:   svc.ID,
		Code: svc.Code,
	}, nil
}
