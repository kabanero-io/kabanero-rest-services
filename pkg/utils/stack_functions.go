// comment
package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	//corev1 "k8s.io/api/core/v1"
	//"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var log = logf.Log.WithName("utils/stack_functions")
var myLogger logr.Logger = log.WithValues("Request.Namespace", "kabanero-rest-service", "Request.Name", "kabanero-rest-service")

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

func getClientClient() (client.Client, error) {
	cl, err := client.New(config.GetConfigOrDie(), client.Options{})
	if err != nil {
		return nil, err
	}
	// if err != nil {
	// 	panic(err.Error())
	// }
	return cl, err
}

func getKabanero() (kabanerov1alpha2.Kabanero, error) {

	var kabaneroInstance kabanerov1alpha2.Kabanero
	kabUnstructured := &unstructured.Unstructured{}
	kabUnstructured.SetKind("Kabanero")
	kabUnstructured.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "Kabanero",
		Group:   kabanerov1alpha2.SchemeGroupVersion.Group,
		Version: kabanerov1alpha2.SchemeGroupVersion.Version,
	})

	ctx := context.Background()
	var err error
	var cl client.Client
	cl, err = getClientClient()
	if err != nil {
		return kabaneroInstance, err
	}
	ns := getHookNamespace()
	n := types.NamespacedName{}
	n.Name = ns
	n.Namespace = ns
	err = cl.Get(ctx, n, kabUnstructured)

	kabaneroBytes, err := kabUnstructured.MarshalJSON()
	if err != nil {
		return kabaneroInstance, err
	}

	json.Unmarshal(kabaneroBytes, &kabaneroInstance)

	return kabaneroInstance, err
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

	var err error
	var cl client.Client
	cl, err = getClientClient()
	if err != nil {
		return stacksUnstructured, err
	}
	ns := getHookNamespace()
	err = cl.List(ctx, stacksUnstructured, client.InNamespace(ns))

	return stacksUnstructured, err
}

func getDeployments(name string, version string, ns string) ([]*models.DescribeStackAppsItems0, error) {
	fmt.Println("entering deployments")
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// if err != nil {
	// 	panic(err.Error())
	// }

	// creates the clientset
	clSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	// if err != nil {
	// 	panic(err.Error())
	// }

	fmt.Println("namespace")
	fmt.Println(ns)
	apps := []*models.DescribeStackAppsItems0{}
	deploymentsClient := clSet.AppsV1().Deployments(ns)
	list, err := deploymentsClient.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	// if err != nil {
	// 	panic(err)
	// }
	for _, d := range list.Items {
		app := models.DescribeStackAppsItems0{}

		deployName := d.ObjectMeta.Labels["stack.appsody.dev/id"]
		deployVersion := d.ObjectMeta.Labels["stack.appsody.dev/version"]

		if deployName == name && deployVersion == version {
			fmt.Println("matched")
			fmt.Println("deployName:")
			fmt.Println(deployName)
			fmt.Println("deployVersions:")
			fmt.Println(deployVersion)
			fmt.Println("labels")
			fmt.Println(d.ObjectMeta.Labels["stack.appsody.dev/id"])
			fmt.Println(d.ObjectMeta.Labels["stack.appsody.dev/version"])

			app.AppKubernetesIoInstance = d.ObjectMeta.Labels["app.kubernetes.io/instance"]
			app.AppKubernetesIoManagedBy = d.ObjectMeta.Labels["app.kubernetes.io/managed-by"]
			app.AppKubernetesIoName = d.ObjectMeta.Labels["app.kubernetes.io/name"]
			app.AppKubernetesIoPartOf = d.ObjectMeta.Labels["app.kubernetes.io/part-of"]
			app.AppKubernetesIoVersion = d.ObjectMeta.Labels["app.kubernetes.io/version"]

			apps = append(apps, &app)
		}
	}
	return apps, err
}

func getApps(ns string, name string, version string) ([]*models.DescribeStackAppsItems0, error) {
	fmt.Println("in getApps():")
	fmt.Println("name:")
	fmt.Println(name)
	fmt.Println("version:")
	fmt.Println(version)

	apps := []*models.DescribeStackAppsItems0{}

	var targetnamespaceList []string
	k, err := getKabanero()
	if err != nil {
		return nil, err
	}
	// if err != nil {
	// 	panic(err)
	// }

	targetnamespaceList = k.Spec.TargetNamespaces

	myapps, err := getDeployments(name, version, ns)

	apps = append(apps, myapps[0])

	for _, nspace := range targetnamespaceList {
		deployapps, err := getDeployments(name, version, nspace)
		if err != nil {
			return nil, err
		}
		// if err != nil {
		// 	panic(err)
		// }
		for _, application := range deployapps {
			apps = append(apps, application)
		}
	}
	return apps, err
}

// list all stacks in namespace
func ListStacksFunc() ([]*models.KabaneroStack, error) {
	fmt.Println("Entered ListStacksFunc!")

	ns := getHookNamespace()

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
			imageNameWVersion := imageName + ":" + dStackStatusVersion.Version
			crDigest, err = retrieveImageDigestFromContainerRegistry(ns, imgRegistry, true, myLogger, imageNameWVersion)
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
			return describeStack, err
		}
		// if err != nil {
		// 	panic(err.Error())
		// }
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
					imageNameWVersion := imageName + ":" + version
					crDigest, err := retrieveImageDigestFromContainerRegistry(ns, imgRegistry, true, myLogger, imageNameWVersion)
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
					apps, err := getApps(ns, name, version)
					if err != nil {
						return describeStack, err
					}
					describeStack.Apps = apps
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
func retrieveImageDigestFromContainerRegistry(namespace string, imgRegistry string, skipCertVerification bool, logr logr.Logger, image string) (string, error) {
	fmt.Println("in retrieveImageDigestFromContainerRegistry:")
	fmt.Printf(" * namespace: %s imgRegistry: %s image: %s\n", namespace, imgRegistry, image)

	config, err := rest.InClusterConfig()
	if err != nil {
		return "", err
	}
	// if err != nil {
	// 	panic(err.Error())
	// }
	// creates the clientset
	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	annotationKey := "tekton.dev/docker-0"
	// annotationKey := "kabanero.io/docker-"
	secretsList, err := c.CoreV1().Secrets(namespace).List(metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	// if err != nil {
	// 	panic(err)
	// }
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
		fmt.Println("<<1>>")
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
		fmt.Println("<<2>>")
		img, err := remote.Image(ref,
			remote.WithAuth(authenticator),
			remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}),
			remote.WithTransport(transport))
		if err != nil {
			return "", err
		}
		fmt.Println("img")
		fmt.Println(img)
		h, err := img.Digest()
		fmt.Println("h")
		fmt.Println(h)
		if err != nil {
			return "", err
		}
		digest = h.Hex
	}

	fmt.Printf(" * digest: %s \n", digest)

	// Get the image's Digest (i.e sha256:8f095a6e...)

	// Return the actual digest part only.
	return digest, nil
}
