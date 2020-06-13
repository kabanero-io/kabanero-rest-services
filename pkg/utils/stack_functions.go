// comment
package utils

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/docker/registry"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	kabanerov1alpha2 "github.com/kabanero-io/kabanero-operator/pkg/apis/kabanero/v1alpha2"
	sutils "github.com/kabanero-io/kabanero-operator/pkg/controller/stack/utils"
	"github.com/kabanero-io/kabanero-operator/pkg/controller/utils/secret"
	"github.com/kabanero-io/kabanero-rest-services/models"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	runtimer "k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var log = logf.Log.WithName("utils/stack_functions")
var myLogger logr.Logger = log.WithValues("Request.Namespace", "kabanero-rest-service", "Request.Name", "kabanero-rest-service")

// -----------------------------------------------------------------------------------------------
// Client struct
// -----------------------------------------------------------------------------------------------
type stackClient struct {
	objs map[string]*kabanerov1alpha2.Stack
}

func (c stackClient) Get(ctx context.Context, key client.ObjectKey, obj runtimer.Object) error {
	fmt.Printf("Received Get() for %v\n", key.Name)
	u, ok := obj.(*kabanerov1alpha2.Stack)
	if !ok {
		fmt.Printf("Received invalid target object for get: %v\n", obj)
		return errors.New("Get only supports stacks")
	}
	stack := c.objs[key.Name]
	if stack == nil {
		return apierrors.NewNotFound(schema.GroupResource{}, key.Name)
	}
	stack.DeepCopyInto(u)
	return nil
}

func (c stackClient) List(ctx context.Context, list runtimer.Object, opts ...client.ListOption) error {
	l, ok := list.(*kabanerov1alpha2.StackList)
	if !ok {
		fmt.Printf("Received an invalid list object: %v\n", list)
		return errors.New("Get only supports stacks")
	}

	stackList := &kabanerov1alpha2.StackList{}
	items := []kabanerov1alpha2.Stack{}
	for _, stack := range c.objs {
		items = append(items, *stack)
	}

	stackList.Items = items
	stackList.DeepCopyInto(l)

	return nil
}

func (c stackClient) Create(ctx context.Context, obj runtimer.Object, opts ...client.CreateOption) error {
	u, ok := obj.(*kabanerov1alpha2.Stack)
	if !ok {
		fmt.Printf("Received invalid create: %v\n", obj)
		return errors.New("Create only supports Stacks")
	}

	fmt.Printf("Received Create() for %v\n", u.Name)
	stack := c.objs[u.Name]
	if stack != nil {
		fmt.Printf("Receive create object already exists: %v\n", u.Name)
		return apierrors.NewAlreadyExists(schema.GroupResource{}, u.Name)
	}

	c.objs[u.Name] = u
	return nil
}

func (c stackClient) Delete(ctx context.Context, obj runtimer.Object, opts ...client.DeleteOption) error {
	u, ok := obj.(*kabanerov1alpha2.Stack)
	if !ok {
		fmt.Printf("Received an invalid delete object: %v\n", obj)
		return errors.New("Update only supports Stack")
	}

	delete(c.objs, u.Name)
	return nil
}

func (c stackClient) DeleteAllOf(ctx context.Context, obj runtimer.Object, opts ...client.DeleteAllOfOption) error {
	return errors.New("DeleteAllOf is not supported")
}

func (c stackClient) Update(ctx context.Context, obj runtimer.Object, opts ...client.UpdateOption) error {
	u, ok := obj.(*kabanerov1alpha2.Stack)
	if !ok {
		fmt.Printf("Received invalid update: %v\n", obj)
		return errors.New("Update only supports Stack")
	}

	fmt.Printf("Received Update() for %v\n", u.Name)
	stack := c.objs[u.Name]
	if stack == nil {
		fmt.Printf("Received update for object that does not exist: %v\n", obj)
		return apierrors.NewNotFound(schema.GroupResource{}, u.Name)
	}
	c.objs[u.Name] = u
	return nil
}
func (c stackClient) Status() client.StatusWriter { return c }
func (c stackClient) Patch(ctx context.Context, obj runtimer.Object, patch client.Patch, opts ...client.PatchOption) error {
	return errors.New("Patch is not supported")
}

func getHookNamespace() (string, error) {
	ns, found := os.LookupEnv("KABANERO_NAMESPACE")
	if !found {
		return "", fmt.Errorf("KABANERO_NAMESPACE must be set")
	}
	return ns, nil
}

// Returns an authenticator object containing basic authentication credentials.
func getBasicSecAuth(username []byte, password []byte) (authn.Authenticator, error) {
	authenticator := authn.FromConfig(authn.AuthConfig{
		Username: string(username),
		Password: string(password)})

	return authenticator, nil
}

// Resolve the server name key to be used when searching for the server name entry in the
// the docker config data or the credential store.
func resolveDockerConfRegKey(imgRegistry string) string {
	var key string
	switch imgRegistry {
	// Docker registry: When logging in to the docker registry, the server name can be either:
	// nothing, docker.io, index.docker.io, or registry-1.docker.io.
	// They are all translated to: https://index.docker.io/v1/ as the server name.
	case registry.IndexName, registry.IndexHostname, registry.DefaultV2Registry.Hostname():
		key = registry.IndexServer
	default:
		key = imgRegistry
	}

	return key
}

// Returns an authenticator object containing docker config credentials.
// It handles both legacy .dockercfg file data and docker.json file data.
func getDockerCfgSecAuth(dockerconfigjson []byte, dockerconfig []byte, imgRegistry string, reqLogger logr.Logger) (authn.Authenticator, error) {
	// Read the docker config data into a configFile object.
	var dcf *configfile.ConfigFile
	if len(dockerconfigjson) != 0 {
		cf, err := config.LoadFromReader(strings.NewReader(string(dockerconfigjson)))
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("Unable to load/map docker config data. Error: %v", err))
		}
		dcf = cf
	} else {
		cf, err := config.LegacyLoadFromReader(strings.NewReader(string(dockerconfig)))
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("Unable to load/map legacy docker config data. Error: %v", err))
		}
		dcf = cf
	}

	// Resolve the key that will be used to search for the server name entry in the docker config data.
	key := resolveDockerConfRegKey(imgRegistry)

	// If the docker config entry in the secret does not have an authentication entry, default
	// to Anonymous authentication.
	if !dcf.ContainsAuth() {
		reqLogger.Info(fmt.Sprintf("Security credentials for server name: %v could not be found. The docker config data did not contain any authentication information.", key))
		return authn.Anonymous, nil
	}

	// Get the security credentials for the given key (servername).
	// The credentials are obtained from the credential store if one setup/configured; otherwise, they are obtained
	// from the docker config data that was read.
	// Note that it is very important that if the image being read contains the registry name as prefix,
	// the registry name must match the server name used when the docker login was issued. For example, if
	// private server: mysevername:5000 is used when issuing a docker login command, it is expected
	// that the part of the image representing the registry should be mysevername:5000 (i.e.
	// mysevername:5000/path/my-image:1.0.0)
	cfg, err := dcf.GetAuthConfig(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve credentials from credentials for server name: Key: %v, Error: %v", key, err)
	}

	// No match was found for the server name key. Default to anonymous authentication.
	if len(cfg.Username) == 0 {
		reqLogger.Info(fmt.Sprintf("Security credentials for server name: %v could not be found. The credential store or docker config data did not contain the security credentials for the mentioned server.", key))
		return authn.Anonymous, nil
	}

	// Security credentials were found.
	authenticator := authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	})

	return authenticator, nil
}

// list all stacks in namespace
func ListStacksFunc() ([]*models.KabaneroStack, error) {
	ctx := context.Background()
	cl := stackClient{make(map[string]*kabanerov1alpha2.Stack)}
	deployedStacks := &kabanerov1alpha2.StackList{}
	listOfStacks := []*models.KabaneroStack{}
	var ns string
	var err error
	ns, err = getHookNamespace()
	err = cl.List(ctx, deployedStacks, client.InNamespace(ns))
	if err != nil {
		return listOfStacks, err
	}

	// Compare the list of currently deployed stacks and the stacks in the index.

	for _, deployedStack := range deployedStacks.Items {
		stack := models.KabaneroStack{}
		stack.Name = deployedStack.GetName()
		items := []models.KabaneroStackStatusItems0{}
		for _, dStackStatusVersion := range deployedStack.Status.Versions {
			item := models.KabaneroStackStatusItems0{}
			item.Status = dStackStatusVersion.Status
			item.Version = dStackStatusVersion.Version
			var imageName string
			var stackDigest string
			for _, imageStatus := range dStackStatusVersion.Images[0:] {
				stackDigest = imageStatus.Digest.Activation
				imageName = imageStatus.Image
			}
			item.KabaneroDigest = stackDigest
			s := strings.Split(imageName, "/")
			imgRegistry := s[0]
			var crDigest string
			crDigest, err = RetrieveImageDigestFromContainerRegistry(cl, ns, imgRegistry, true, myLogger, imageName)
			item.ImageDigest = crDigest
			item.DigestCheck = DigestCheck(stackDigest, crDigest, item.Status)
			items = append(items, item)
		}
		listOfStacks = append(listOfStacks, &stack)
	}

	return listOfStacks, err
}

// describe stack in detail
func DescribeStackFunc(name string, version string) (models.DescribeStack, error) {
	ctx := context.Background()
	cl := stackClient{make(map[string]*kabanerov1alpha2.Stack)}
	deployedStacks := &kabanerov1alpha2.StackList{}
	var stack models.DescribeStack
	var ns string
	var err error
	ns, err = getHookNamespace()
	err = cl.List(ctx, deployedStacks, client.InNamespace(ns))
	if err != nil {
		return stack, err
	}

	for _, deployedStack := range deployedStacks.Items {
		stackName := deployedStack.GetName()
		if stackName == name {
			for _, dStackStatusVersion := range deployedStack.Status.Versions {
				if dStackStatusVersion.Version == version {
					var stackDigest string
					for _, imageStatus := range dStackStatusVersion.Images[0:] {
						stackDigest = imageStatus.Digest.Activation
						stack.Image = imageStatus.Image
					}
					s := strings.Split(stack.Image, "/")
					imgRegistry := s[0]
					crDigest, err := RetrieveImageDigestFromContainerRegistry(cl, ns, imgRegistry, true, myLogger, stack.Image)
					if err != nil {
						return stack, err
					}
					stack.Name = name
					stack.Version = version
					stack.Status = dStackStatusVersion.Status
					stack.DigestCheck = DigestCheck(stackDigest, crDigest, dStackStatusVersion.Status)
					stack.KabaneroDigest = stackDigest
					stack.ImageDigest = crDigest
					stack.Project = ns
					break
				}
			}
		}
	}
	return stack, err
}

// compares digest to make sure they are identical
func DigestCheck(stackDigest string, crDigest string, status string) string {
	var digestCheck string
	digestCheck = "mismatched"
	if len(stackDigest) != 0 && len(crDigest) != 0 {
		if stackDigest == crDigest {
			digestCheck = "matched"
		} else if strings.Contains(crDigest, "not found in container registry") {
			digestCheck = crDigest
			return digestCheck
		}
	} else {
		fmt.Sprintf("Could not find one of the digests, stack digest %s, cr digest %s", stackDigest, crDigest)
		digestCheck = "unknown"
		return digestCheck
	}
	if len(status) != 0 {
		if strings.Contains(status, "active") {
			statusRune := []rune(status)
			shortStatus := string(statusRune[0:6])
			if shortStatus != "active" {
				digestCheck = "NA"
			}
		} else {
			digestCheck = "NA"
		}
	} else {
		digestCheck = "NA"
	}

	return digestCheck
}

// Retrieves the input image digest from the hosting repository.
func RetrieveImageDigestFromContainerRegistry(c client.Client, namespace string, imgRegistry string, skipCertVerification bool, logr logr.Logger, image string) (string, error) {

	// Search all secrets under the given namespace for the one containing the required hostname.
	annotationKey := "kabanero.io/docker-"
	secret, err := secret.GetMatchingSecret(c, namespace, sutils.SecretAnnotationFilter, imgRegistry, annotationKey)
	// if err != nil {
	// 	newError := fmt.Errorf("Unable to find secret matching annotation values: %v and %v in namespace %v Error: %v", annotationKey, imgRegistry, namespace, err)
	// 	return "", newError
	// }

	// If a secret was found, retrieve the needed information from it.
	var password []byte
	var username []byte
	var dockerconfig []byte
	var dockerconfigjson []byte

	if secret != nil {
		logr.Info(fmt.Sprintf("Secret used for image registry access: %v. Secret annotations: %v", secret.GetName(), secret.Annotations))
		username, _ = secret.Data[corev1.BasicAuthUsernameKey]
		password, _ = secret.Data[corev1.BasicAuthPasswordKey]
		dockerconfig, _ = secret.Data[corev1.DockerConfigKey]
		dockerconfigjson, _ = secret.Data[corev1.DockerConfigJsonKey]
	}

	// Create the authenticator mechanism to use for authentication.
	authenticator := authn.Anonymous
	if len(username) != 0 && len(password) != 0 {
		authenticator, err = getBasicSecAuth(username, password)
		if err != nil {
			return "", err
		}
	} else if len(dockerconfig) != 0 || len(dockerconfigjson) != 0 {
		authenticator, err = getDockerCfgSecAuth(dockerconfigjson, dockerconfig, imgRegistry, logr)
		if err != nil {
			return "", err
		}
	}

	// Retrieve the image manifest.
	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{}
	if skipCertVerification {
		tlsConf := &tls.Config{InsecureSkipVerify: skipCertVerification}
		transport.TLSClientConfig = tlsConf
	}
	var digest string
	if secret == nil {
		img, err := remote.Image(ref,
			remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}),
			remote.WithTransport(transport))
		if err != nil {
			return "cannot read registry without credentials, please configure a secret to supply them", err
		}
		h, err := img.Digest()
		if err != nil {
			return "", err
		}
		digest = h.Hex
	} else {
		img, err := remote.Image(ref,
			remote.WithAuth(authenticator),
			remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}),
			remote.WithTransport(transport))
		if err != nil {
			return "", err
		}
		h, err := img.Digest()
		if err != nil {
			return "", err
		}
		digest = h.Hex
	}

	// Get the image's Digest (i.e sha256:8f095a6e...)

	// Return the actual digest part only.
	return digest, nil
}

// this code may change to just use unstructured eventually
// e.g.
//
// func getCRWInstance(ctx context.Context, k *kabanerov1alpha2.Kabanero, c client.Client) (*unstructured.Unstructured, error) {
// 	crwInst := &unstructured.Unstructured{}
// 	crwInst.SetGroupVersionKind(schema.GroupVersionKind{
// 		Kind:    "CheCluster",
// 		Group:   "org.eclipse.che",
// 		Version: "v1",
// 	})
// 	err := c.Get(ctx, client.ObjectKey{
// 		Name:      crwOperatorCRNameSuffix,
// 		Namespace: k.ObjectMeta.Namespace}, crwInst)
// 	return crwInst, err
// }
// server, found, err := unstructured.NestedFieldCopy(crwInst.Object, "spec", "server")

// stackInst := &unstructured.Unstructured{}
// 	crwInst.SetGroupVersionKind(schema.GroupVersionKind{
// 		Kind:    "CheCluster",
// 		Group:   "org.eclipse.che",
// 		Version: "v1",
// 	})
