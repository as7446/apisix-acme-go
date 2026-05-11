package handler

import (
	"github.com/as7446/apisix-acme-go/internal/application"
)

// Container Handler 容器
type Container struct {
	Task  *TaskHandler
	Cert  *CertHandler
	Agent *AgentHandler
}

// NewContainer 创建 Handler 容器
func NewContainer(
	taskSvc *application.TaskService,
	certSvc *application.CertService,
	agentSvc *application.AgentService,
) *Container {
	return &Container{
		Task:  NewTaskHandler(taskSvc),
		Cert:  NewCertHandler(certSvc),
		Agent: NewAgentHandler(agentSvc),
	}
}
