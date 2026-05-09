package storm

import (
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
)

// acmeAccountRecord Storm 存储层模型
type acmeAccountRecord struct {
	Email        string `storm:"id"`
	PrivateKey   []byte
	Registration []byte
	CreatedAt    int64 `storm:"index"`
}

// AccountRepo ACME 账户存储
type AccountRepo struct {
	store *Store
}

// NewAccountRepo 创建 AccountRepo
func NewAccountRepo(s *Store) *AccountRepo {
	return &AccountRepo{store: s}
}

func (r *AccountRepo) GetAccount(email string) (*cert.AcmeAccount, error) {
	var rec acmeAccountRecord
	err := r.store.DB.One("Email", email, &rec)
	if err != nil {
		return nil, err
	}
	return &cert.AcmeAccount{
		Email: rec.Email, PrivateKey: rec.PrivateKey,
		Registration: rec.Registration, CreatedAt: rec.CreatedAt,
	}, nil
}

func (r *AccountRepo) SaveAccount(account *cert.AcmeAccount) error {
	if account.CreatedAt == 0 {
		account.CreatedAt = time.Now().Unix()
	}
	rec := acmeAccountRecord{
		Email: account.Email, PrivateKey: account.PrivateKey,
		Registration: account.Registration, CreatedAt: account.CreatedAt,
	}
	return r.store.DB.Save(&rec)
}
