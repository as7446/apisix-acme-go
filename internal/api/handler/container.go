package handler

import (
	"github.com/as7446/apisix-acme-go/internal/application"
	"github.com/as7446/apisix-acme-go/internal/controller/dispatch"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
)

// Container Handler 容器
type Container struct {
	Certificate *CertificateHandler
	Agent       *AgentHandler
	AgentTask   *AgentTaskHandler
}

// NewContainer 创建 Handler 容器
func NewContainer(
	commandSvc *application.CertCommandService,
	certSvc *application.CertService,
	agentSvc *application.AgentService,
	dispatcher *dispatch.TaskDispatcher,
	cfg *config.Config,
) *Container {
	c := &Container{
		Certificate: NewCertificateHandler(commandSvc, certSvc),
		Agent:       NewAgentHandler(agentSvc),
	}
	if dispatcher != nil {
		c.AgentTask = NewAgentTaskHandler(dispatcher, cfg)
	}
	return c
}
