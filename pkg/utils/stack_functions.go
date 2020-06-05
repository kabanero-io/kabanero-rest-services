package utils

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	kabanerov1alpha2 "github.com/kabanero-io/kabanero-operator/pkg/apis/kabanero/v1alpha2"
	"github.com/kabanero-io/kabanero-operator/pkg/controller/kabaneroplatform/utils"
	cutils "github.com/kabanero-io/kabanero-operator/pkg/controller/kabaneroplatform/utils"
	"github.com/kabanero-io/kabanero-operator/pkg/controller/stack"
	sutils "github.com/kabanero-io/kabanero-operator/pkg/controller/stack/utils"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// -----------------------------------------------------------------------------------------------
// Client that creates/deletes stacks.
// -----------------------------------------------------------------------------------------------
type stackClient struct {
	objs map[string]*kabanerov1alpha2.Stack
}

func listStacksInKabanero(k *kabanerov1alpha2.Kabanero) error {
	ctx := context.Background()
	cl := stackClient{map[client.ObjectKey][]metav1.OwnerReference{}}
	deployedStacks := &kabanerov1alpha2.StackList{}
	err := cl.List(ctx, deployedStacks, client.InNamespace(k.GetNamespace()))
	if err != nil {
		return err
	}
	
	// Compare the list of currently deployed stacks and the stacks in the index.
	var stackMapList []M
	for _, deployedStack := range deployedStacks.Items {
		stackMap := make(map[string]interface{})
		stackMap["name"] = deployedStack.Spec.nameame
		var versionMapList []M
		for _, dStackVersion := range deployedStack.Spec.Versions {
			versionMap := make(map[string]string)
			status := dStackVersion.Status.status
			versionMap["status"] = status
			versionMap["version"] = dStackVersion.Status.version
			stack_digest := dStackVersion.Images.digest.activation
			imageName :=  dStackVersion.Images.image
			s := strings.Split(imageName, "/")
			imgRegistry := s[0]
			cr_digest := retrieveImageDigestFromCR(cl, namespace, imgRegistry , true, logr logr.Logger, imageName)
			versionMap["stack digest"] = stack_digest
			versionMap["cr digest"] = cr_digest
			versionMap["digestCheck"] = digestCheck(stack_digest, cr_digest, status)
			versionMapList = append(versionMapList, versionMap)	
		}
		stackMap["version"] = versionMapList
		stackMapList = append(stackMapList, stackMap)
	}
	return json.Marshall(stackMapList)
}

func digestCheck(stack_digest string, cr_digest string, status string) {
	digestCheck = "mismatched"
		if stack_digest != nil && cr_digest != nil {
			if stack_digest == cr_digest  {
				digestCheck="matched";
			} else if strings.contains(cr_digest.contains, "not found in container registry") {
				digestCheck = imageDigest;
				return digestCheck
			}
		} else {
			fmt.Sprintf("Could not find one of the digests, stack digest %s, cr digest %s", stack_digest, cr_digest)
			digestCheck="unknown"
			return digestCheck
		}
		if status != nil {
			if strings.contains(status, "active") {
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

func describeStack(k *kabanerov1alpha2.Kabanero) error {
	ctx := context.Background()
	cl := stackClient{map[client.ObjectKey][]metav1.OwnerReference{}}
	deployedStacks := &kabanerov1alpha2.StackList{}
	err := cl.List(ctx, deployedStacks, client.InNamespace(k.GetNamespace()))
	if err != nil {
		return err
	}
	return deployedStacks
}


// Retrieves the input image digest from the hosting repository.
func retrieveImageDigestFromCR(c client.Client, namespace string, imgRegistry string, skipCertVerification bool, logr logr.Logger, image string) (string, error) {
	
	// Search all secrets under the given namespace for the one containing the required hostname.
	annotationKey := "kabanero.io/docker-"
	secret, err := secret.GetMatchingSecret(c, namespace, sutils.SecretAnnotationFilter, imgRegistry, annotationKey)
	if err != nil {
		newError := fmt.Errorf("Unable to find secret matching annotation values: %v and %v in namespace %v Error: %v", annotationKey, imgRegistry, namespace, err)
		return "", newError
	}

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

	img, err := remote.Image(ref,
		remote.WithAuth(authenticator),
		remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}),
		remote.WithTransport(transport))
	if err != nil {
		return "", err
	}

	// Get the image's Digest (i.e sha256:8f095a6e...)
	h, err := img.Digest()
	if err != nil {
		return "", err
	}

	// Return the actual digest part only.
	return h.Hex, nil
}