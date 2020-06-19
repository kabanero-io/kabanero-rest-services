// comment
package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/docker/docker/registry"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	kabanerov1alpha2 "github.com/kabanero-io/kabanero-operator/pkg/apis/kabanero/v1alpha2"
	"github.com/kabanero-io/kabanero-rest-services/models"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	runtimer "k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	//corev1 "k8s.io/api/core/v1"
	//"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

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

func getHookNamespace() string {
	ns := os.Getenv("KABANERO_CLI_NAMESPACE")
	return ns
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

func getClientClient() client.Client {
	cl, err := client.New(config.GetConfigOrDie(), client.Options{})
	if err != nil {
		panic(err.Error())
	}
	return cl
}

func getStacks() (*unstructured.UnstructuredList, error) {
	stacksUnstructured := &unstructured.UnstructuredList{}
	stacksUnstructured.SetKind("Stack")
	stacksUnstructured.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "Stack",
		Group:   kabanerov1alpha2.SchemeGroupVersion.Group,
		Version: kabanerov1alpha2.SchemeGroupVersion.Version,
	})

	ctx := context.Background()
	cl := getClientClient()
	ns := getHookNamespace()
	err := cl.List(ctx, stacksUnstructured, client.InNamespace(ns))

	return stacksUnstructured, err
}

// list all stacks in namespace
func ListStacksFunc() ([]*models.KabaneroStack, error) {
	fmt.Println("Entered ListStacksFunc!")

	ns := getHookNamespace()
	fmt.Println("namespace:")
	fmt.Println(ns)

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	deploymentsClient := clSet.AppsV1().Deployments(ns)
	list, err := deploymentsClient.List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, d := range list.Items {
		fmt.Printf(" * %s \n", d.Name)
		fmt.Println("labels")
		fmt.Println(d.ObjectMeta.Labels["stack.appsody.dev/id"])
		fmt.Println(d.ObjectMeta.Labels["stack.appsody.dev/version"])
	}

	fmt.Println("<<1.0>>")

	// stacksUnstructured := &unstructured.UnstructuredList{}
	// stacksUnstructured.SetKind("Stack")
	// stacksUnstructured.SetGroupVersionKind(schema.GroupVersionKind{
	// 	Kind:    "Stack",
	// 	Group:   kabanerov1alpha2.SchemeGroupVersion.Group,
	// 	Version: kabanerov1alpha2.SchemeGroupVersion.Version,
	// })

	// ctx := context.Background()
	// cl := getClientClient()

	// err = cl.List(ctx, stacksUnstructured, client.InNamespace(ns))

	stacksUnstructured, err := getStacks()

	listOfStacks := []*models.KabaneroStack{}
	for _, onestack := range stacksUnstructured.Items {
		fmt.Println("Stack:")
		stack := models.KabaneroStack{}
		oneStackBytes, err := onestack.MarshalJSON()
		if err != nil {
			panic(err.Error())
		}
		var kabstack kabanerov1alpha2.Stack
		json.Unmarshal(oneStackBytes, &kabstack)
		stack.Name = kabstack.GetName()
		fmt.Println("Stack Name:")
		fmt.Println(stack.Name)
		items := []*models.KabaneroStackStatusItems0{}
		for _, dStackStatusVersion := range kabstack.Status.Versions {
			item := models.KabaneroStackStatusItems0{}
			fmt.Println(dStackStatusVersion.Status)
			fmt.Println(dStackStatusVersion.Version)
			var imageName string
			var stackDigest string
			for _, imageStatus := range dStackStatusVersion.Images[0:] {
				stackDigest = imageStatus.Digest.Activation
				imageName = imageStatus.Image
			}
			item.KabaneroDigest = stackDigest
			s := strings.Split(imageName, "/")
			imgRegistry := s[0]
			fmt.Println("imgRegistry:")
			fmt.Println(imgRegistry)
			var crDigest string
			crDigest, err = RetrieveImageDigestFromContainerRegistry(ns, imgRegistry, true, myLogger, imageName)
			fmt.Println("crDigest:")
			fmt.Println(crDigest)
			item.ImageName = imageName
			item.Status = dStackStatusVersion.Status
			item.Version = dStackStatusVersion.Version
			item.ImageDigest = crDigest
			item.DigestCheck = DigestCheck(stackDigest, crDigest, item.Status)
			fmt.Println("item:")
			fmt.Println(item)
			items = append(items, &item)
			stack.Status = items
		}
		listOfStacks = append(listOfStacks, &stack)
	}

	fmt.Println("<<3>>")
	return listOfStacks, err
}

// describe stack in detail
func DescribeStackFunc(name string, version string) (models.DescribeStack, error) {
	var err error
	ns := getHookNamespace()

	describeStack := models.DescribeStack{}
	stacksUnstructured, err := getStacks()

	for _, onestack := range stacksUnstructured.Items {
		oneStackBytes, err := onestack.MarshalJSON()
		if err != nil {
			panic(err.Error())
		}
		var kabstack kabanerov1alpha2.Stack
		json.Unmarshal(oneStackBytes, &kabstack)
		nameFromStack := kabstack.GetName()
		if nameFromStack == name {
			for _, dStackStatusVersion := range kabstack.Status.Versions {
				if dStackStatusVersion.Version == version {
					var stackDigest string
					var imageName string
					for _, imageStatus := range dStackStatusVersion.Images[0:] {
						stackDigest = imageStatus.Digest.Activation
						imageName = imageStatus.Image
					}
					s := strings.Split(imageName, "/")
					imgRegistry := s[0]
					crDigest, err := RetrieveImageDigestFromContainerRegistry(ns, imgRegistry, true, myLogger, imageName)
					if err != nil {
						return describeStack, err
					}
					describeStack.Name = kabstack.GetName()
					describeStack.ImageName = imageName
					describeStack.KabaneroDigest = stackDigest
					describeStack.Status = dStackStatusVersion.Status
					describeStack.Version = dStackStatusVersion.Version
					describeStack.ImageDigest = crDigest
					describeStack.DigestCheck = DigestCheck(stackDigest, crDigest, dStackStatusVersion.Status)
					describeStack.Project = ns
					break
				}
			}
		}
	}
	return describeStack, err
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
func RetrieveImageDigestFromContainerRegistry(namespace string, imgRegistry string, skipCertVerification bool, logr logr.Logger, image string) (string, error) {

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	annotationKey := "tekton.dev/docker-0"
	// annotationKey := "kabanero.io/docker-"
	secretsList, err := c.CoreV1().Secrets(namespace).List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	var hostName string
	var username []byte
	var password []byte
	//var seccret corev1.Secret
	for _, secret := range secretsList.Items {
		hostName = secret.ObjectMeta.Annotations[annotationKey]
		//fmt.Printf(" * hostname: %s \n", imgRegistry)
		if strings.Contains(hostName, "docker.io") {
			username = secret.Data["username"]
			password = secret.Data["password"]
			//seccret = secret
			//fmt.Printf(" * user: %s password: %s\n", username, password)
			break
		}
	}

	// Create the authenticator mechanism to use for authentication.
	authenticator := authn.Anonymous
	if len(username) != 0 && len(password) != 0 {
		authenticator, err = getBasicSecAuth(username, password)
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
	if len(username) == 0 {
		img, err := remote.Image(ref,
			remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}),
			remote.WithTransport(transport))
		if err != nil {
			return "cannot read registry without credentials", err
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
