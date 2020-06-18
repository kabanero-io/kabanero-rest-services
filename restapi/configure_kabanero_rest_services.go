// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-openapi/swag"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/kabanero-io/kabanero-rest-services/models"
	"github.com/kabanero-io/kabanero-rest-services/pkg/utils"
	"github.com/kabanero-io/kabanero-rest-services/restapi/operations"
	"github.com/kabanero-io/kabanero-rest-services/restapi/operations/message"
)

//go:generate swagger generate server --target ../../kabanero-rest-services --name KabaneroRestServices --spec ../swagger.yml

func configureFlags(api *operations.KabaneroRestServicesAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.KabaneroRestServicesAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	api.MessageGetTestHandler = message.GetTestHandlerFunc(func(params message.GetTestParams) middleware.Responder {
		fmt.Println("Entered MessageGetTestHandler!")
		return message.NewGetOK().WithPayload(&models.Message{Message: swag.String("HIIIIIIIIIIIIXXXXX")})
	})

	if api.MessageGetHandler == nil {
		api.MessageGetHandler = message.GetHandlerFunc(func(params message.GetParams) middleware.Responder {
			return middleware.NotImplemented("operation message.Get has not yet been implemented")
		})
	}

	api.DescribeHandler = operations.DescribeHandlerFunc(func(params operations.DescribeParams) middleware.Responder {
		fmt.Println("Entered DescribeHandler!")
		// for i := 0; i < 1000; i++ {
		// fmt.Println("Entered DescribeHandler!")
		// }
		fmt.Println("Entered DescribeHandler!")
		describeStack, err := utils.DescribeStackFunc(params.StackName, params.Version)
		if err != nil {
			return operations.NewDescribeOK().WithPayload(&describeStack)
		}
		return operations.NewDescribeOK().WithPayload(&describeStack)
	})

	api.ListHandler = operations.ListHandlerFunc(func(params operations.ListParams) middleware.Responder {
		fmt.Println("Entered ListHandler!")
		fmt.Println("Entered ListHandler!")
		listOfStacks, err := utils.ListStacksFunc()
		if err != nil {
			return operations.NewListOK().WithPayload(listOfStacks)
		}
		return operations.NewListOK().WithPayload(listOfStacks)
	})

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {

}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
