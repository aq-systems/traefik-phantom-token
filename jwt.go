package traefik_phantom_token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	OpaUrl                   string
	OpaAllowField            string
	PayloadFields            []string
	Required                 bool
	AdditionalKeys           []string
	Alg                      string
	Iss                      string
	Aud                      string
	OpaHeaders               map[string]string
	JwtHeaders               map[string]string

	OpenIdConfigUrl  	   string
	ForwardAuthHeader      string
	ForwardAuthErrorHeader string
	EnableMagicToken       bool
	MagicToken             string
	MagicTokenForwardAuth  string
}

type OpenIdConfig struct {
	JwksUri     string `json:"jwks_uri"`
	UserInfoUri string `json:"userinfo_endpoint"`
}

// CreateConfig creates a new OPA Config
func CreateConfig() *Config {
	return &Config{}
}

// JwtPlugin contains the runtime config
type JwtPlugin struct {
	next                   http.Handler
	opaUrl                 string
	opaAllowField          string
	payloadFields          []string
	required               bool

	jwkEndpoints           []*url.URL
	openIdConfigUrl        *url.URL
	forwardAuthHeader      string
	forwardAuthErrorHeader string
	enableMagicToken       bool
	magicToken             string
	magicTokenForwardAuth  string

	openIdConfig       *OpenIdConfig
	keys               map[string]interface{}
	alg                string
	iss                string
	aud                string
	opaHeaders         map[string]string
	jwtHeaders         map[string]string
}

// LogEvent contains a single log entry
type LogEvent struct {
	Level   string    `json:"level"`
	Msg     string    `json:"msg"`
	Time    time.Time `json:"time"`
	Network `json:"network"`
	URL     string `json:"url"`
	Sub     string `json:"sub"`
}

type Network struct {
	Client `json:"client"`
}

type Client struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type JwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}

type JWT struct {
	Plaintext []byte
	Signature []byte
	Header    JwtHeader
	Payload   map[string]interface{}
}

var supportedHeaderNames = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}}

// Key is a JSON web key returned by the JWKS request.
type Key struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	K   string   `json:"k,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	D   string   `json:"d,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	Crv string   `json:"crv,omitempty"`
}

// Keys represents a set of JSON web keys.
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []Key `json:"keys"`
}

// PayloadInput is the input payload
type PayloadInput struct {
	Host       string                 `json:"host"`
	Method     string                 `json:"method"`
	Path       []string               `json:"path"`
	Parameters url.Values             `json:"parameters"`
	Headers    map[string][]string    `json:"headers"`
	JWTHeader  JwtHeader              `json:"tokenHeader"`
	JWTPayload map[string]interface{} `json:"tokenPayload"`
	Body       map[string]interface{} `json:"body,omitempty"`
	Form       url.Values             `json:"form,omitempty"`
}

// Payload for OPA requests
type Payload struct {
	Input *PayloadInput `json:"input"`
}

// Response from OPA
type Response struct {
	Result map[string]json.RawMessage `json:"result"`
}

// New creates a new plugin
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	openIdConfigUrl, err := url.Parse(config.OpenIdConfigUrl)
	if err != nil {
		return nil, err
	}
	jwtPlugin := &JwtPlugin{
		next:          next,
		opaUrl:        config.OpaUrl,
		opaAllowField: config.OpaAllowField,
		payloadFields: config.PayloadFields,
		required:      config.Required,
		alg:           config.Alg,
		iss:           config.Iss,
		aud:           config.Aud,
		keys:          make(map[string]interface{}),
		jwkEndpoints:  make([]*url.URL, 0),
		jwtHeaders:    config.JwtHeaders,
		opaHeaders:    config.OpaHeaders,
		openIdConfig:  &OpenIdConfig{},
		openIdConfigUrl: openIdConfigUrl,
		enableMagicToken: config.EnableMagicToken,
		magicToken: config.MagicToken,
		magicTokenForwardAuth: config.MagicTokenForwardAuth,
		forwardAuthHeader: config.ForwardAuthHeader,
		forwardAuthErrorHeader: config.ForwardAuthErrorHeader,
	}
	if err := jwtPlugin.ParseKeys(config.AdditionalKeys); err != nil {
		return nil, err
	}
	go jwtPlugin.BackgroundRefresh()
	return jwtPlugin, nil
}

func (jwtPlugin *JwtPlugin) BackgroundRefresh() {
	for {
		jwtPlugin.FetchOpenIdConfig()
		fmt.Println("traefik-phantom-token:", jwtPlugin.openIdConfig)
		// add the jwks from the openId config to the list of keys
		if openIdJwks, err := url.ParseRequestURI(jwtPlugin.openIdConfig.JwksUri); err != nil {
			if openIdJwks.String() != "" {
				jwtPlugin.jwkEndpoints = append(jwtPlugin.jwkEndpoints, openIdJwks)
			}
		} else {
			fmt.Println("traefik-phantom-token:", err)
		}
		jwtPlugin.FetchKeys()
		time.Sleep(15 * time.Minute) // 15 min
	}
}

func (jwtPlugin *JwtPlugin) ParseKeys(certificates []string) error {
	for _, certificate := range certificates {
		if block, rest := pem.Decode([]byte(certificate)); block != nil {
			if len(rest) > 0 {
				return fmt.Errorf("extra data after a PEM certificate block")
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse a PEM certificate: %v", err)
				}
				jwtPlugin.keys[base64.RawURLEncoding.EncodeToString(cert.SubjectKeyId)] = cert.PublicKey
			} else if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
				key, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse a PEM public key: %v", err)
				}
				jwtPlugin.keys[strconv.Itoa(len(jwtPlugin.keys))] = key
			} else {
				return fmt.Errorf("failed to extract a Key from the PEM certificate")
			}
		} else if u, err := url.ParseRequestURI(certificate); err == nil {
			jwtPlugin.jwkEndpoints = append(jwtPlugin.jwkEndpoints, u)
		} else {
			return fmt.Errorf("Invalid configuration, expecting a certificate, public key or JWK URL")
		}
	}

	return nil
}

func (jwtPlugin *JwtPlugin) FetchOpenIdConfig() {
	fmt.Println("traefik-phantom-token:", "loading openid-config from the url:", jwtPlugin.openIdConfigUrl.String())
	client := &http.Client{}
	introspectReq, err := http.NewRequest("GET", jwtPlugin.openIdConfigUrl.String(), nil)
	openIdConfigResp, err := client.Do(introspectReq)
	if err != nil {
		fmt.Println(err)
		return
	}
	openIdRes, err := io.ReadAll(openIdConfigResp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	var oc OpenIdConfig
	err = json.Unmarshal(openIdRes, &oc)
	if err != nil {
		fmt.Println(err)
	}
	jwtPlugin.openIdConfig = &oc
	fmt.Println("traefik-phantom-token:", "openid-config loaded")
}

func (jwtPlugin *JwtPlugin) FetchKeys() {
	fmt.Println("-------", jwtPlugin.jwkEndpoints)
	for _, u := range jwtPlugin.jwkEndpoints {
		response, err := http.Get(u.String())
		if err != nil {
			fmt.Println("traefik-phantom-token:", err)
			continue
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("traefik-phantom-token:", err)
			continue
		}
		var jwksKeys Keys
		err = json.Unmarshal(body, &jwksKeys)
		if err != nil {
			fmt.Println("traefik-phantom-token:", err)
			continue
		}
		for _, key := range jwksKeys.Keys {
			switch key.Kty {
			case "RSA":
				{
					if key.Kid == "" {
						key.Kid, err = JWKThumbprint(fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, key.E, key.N))
						if err != nil {
							break
						}
					}
					nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						break
					}
					eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						break
					}
					jwtPlugin.keys[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Uint64())}
				}
			case "EC":
				{
					if key.Kid == "" {
						key.Kid, err = JWKThumbprint(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, key.X, key.Y))
						if err != nil {
							break
						}
					}
					var crv elliptic.Curve
					switch key.Crv {
					case "P-256":
						crv = elliptic.P256()
					case "P-384":
						crv = elliptic.P384()
					case "P-521":
						crv = elliptic.P521()
					default:
						switch key.Alg {
						case "ES256":
							crv = elliptic.P256()
						case "ES384":
							crv = elliptic.P384()
						case "ES512":
							crv = elliptic.P521()
						default:
							crv = elliptic.P256()
						}
					}
					xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
					if err != nil {
						break
					}
					yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
					if err != nil {
						break
					}
					jwtPlugin.keys[key.Kid] = &ecdsa.PublicKey{Curve: crv, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
				}
			case "oct":
				{
					kBytes, err := base64.RawURLEncoding.DecodeString(key.K)
					if err != nil {
						break
					}
					if key.Kid == "" {
						key.Kid, err = JWKThumbprint(key.K)
						if err != nil {
							break
						}
					}
					jwtPlugin.keys[key.Kid] = kBytes
				}
			}
		}
	}
}

func (jwtPlugin *JwtPlugin) ServeHTTP(rw http.ResponseWriter, origReq *http.Request) {
	client := &http.Client{}

	// take token from initial request
	token := origReq.Header.Get("Authorization")
	token = strings.TrimSpace(token)
	token = strings.Replace(token, "Bearer ", "", 1)

	// if no auth header then forward to downstream with an error
	// and ignore calling introspect url
	if len(token) <= 0 {
		jwtPlugin.ForwardError(rw, "Unauthorized", http.StatusUnauthorized, origReq)
		return
	}

	// if magic token mode is enable, which is for testing tools to bypass auth with a fake user
	// then skip the auth check stage and forward on a mocked token
	if jwtPlugin.enableMagicToken {
		if token == jwtPlugin.magicToken {
			// remove Authorization header from original request
			origReq.Header.Del(jwtPlugin.forwardAuthErrorHeader)
			origReq.Header.Set(jwtPlugin.forwardAuthHeader, jwtPlugin.magicTokenForwardAuth)

			jwtPlugin.next.ServeHTTP(rw, origReq)
			return
		}
	}

	// Verify the token against the passed in JWKs
	err, jwtPayload := jwtPlugin.CheckToken(token)
	if err != nil {
		fmt.Println("traefik-phantom-token:", err)
		jwtPlugin.ForwardError(rw, "Unauthorized", http.StatusUnauthorized, origReq)
		return
	}
	if jwtPlugin.opaUrl != "" {
		if err := jwtPlugin.CheckOpa(origReq, jwtPayload); err != nil {
			fmt.Println("traefik-phantom-token:", err)
			jwtPlugin.ForwardError(rw, "Unauthorized", http.StatusUnauthorized, origReq)
			return
		}
	}

	introspectReq, err := http.NewRequest("GET", jwtPlugin.openIdConfig.UserInfoUri, nil)
	// headers
	introspectReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// remove auth headers from forwarded request
	rw.Header().Del(jwtPlugin.forwardAuthHeader)
	rw.Header().Del(jwtPlugin.forwardAuthErrorHeader)
	rw.Header().Del("Authorization")
	origReq.Header.Del(jwtPlugin.forwardAuthHeader)
	origReq.Header.Del(jwtPlugin.forwardAuthErrorHeader)
	origReq.Header.Del("Authorization")

	userInfoResp, err := client.Do(introspectReq)
	if err != nil {
		fmt.Println("traefik-phantom-token:", err)
		jwtPlugin.ForwardError(rw, "gateway 500: failed to introspect token", http.StatusInternalServerError, origReq)
		return
	}
	defer userInfoResp.Body.Close()
	fmt.Println("traefik-phantom-token:", introspectReq.URL, userInfoResp.StatusCode)

	// reject if status code is not 200
	if userInfoResp.StatusCode != http.StatusOK {
		fmt.Printf("traefik-phantom-token: Response (%d) != %d\n", userInfoResp.StatusCode, http.StatusOK)
		jwtPlugin.ForwardError(rw, "Unauthorized", http.StatusUnauthorized, origReq)
		return
	}

	userInfo, err := io.ReadAll(userInfoResp.Body)
	if err != nil {
		fmt.Println("traefik-phantom-token:", err)
		jwtPlugin.ForwardError(rw, "gateway 500: failed to read JWT", http.StatusInternalServerError, origReq)
		return
	}

	// add X-Forward-Auth: b64({JSON}) header
	str := base64.StdEncoding.EncodeToString(userInfo)
	fmt.Println("traefik-phantom-token: base64 ", str)

	// remove Authorization header from original request
	origReq.Header.Del(jwtPlugin.forwardAuthErrorHeader)
	origReq.Header.Set(jwtPlugin.forwardAuthHeader, str)

	jwtPlugin.next.ServeHTTP(rw, origReq)
}

func (jwtPlugin *JwtPlugin) CheckToken(rawAuthHeader string) (error, *JWT) {
	jwtToken, err := jwtPlugin.ExtractToken(rawAuthHeader)
	if err != nil {
		return err, nil
	}
	if jwtToken != nil {
		// only verify jwt tokens if keys are configured
		if len(jwtPlugin.keys) > 0 || len(jwtPlugin.jwkEndpoints) > 0 {
			if err = jwtPlugin.VerifyToken(jwtToken); err != nil {
				return err, nil
			}
		}
		for _, fieldName := range jwtPlugin.payloadFields {
			if _, ok := jwtToken.Payload[fieldName]; !ok {
				if jwtPlugin.required {
					return fmt.Errorf("payload missing required field %s", fieldName), nil
				} else {
					sub := fmt.Sprint(jwtToken.Payload["sub"])
					jsonLogEvent, _ := json.Marshal(&LogEvent{
						Level:   "warning",
						Msg:     fmt.Sprintf("Missing JWT field %s", fieldName),
						Time:    time.Now(),
						Sub:     sub,
					})
					fmt.Println("traefik-phantom-token:", jsonLogEvent)
				}
			}
		}
	}
	return nil, jwtToken
}

func (jwtPlugin *JwtPlugin) ExtractToken(rawAuthHeader string) (*JWT, error) {
	parts := strings.Split(rawAuthHeader, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	jwtToken := JWT{
		Plaintext: []byte(rawAuthHeader[0 : len(parts[0])+len(parts[1])+1]),
		Signature: signature,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		return nil, err
	}
	return &jwtToken, nil
}

func (jwtPlugin *JwtPlugin) remoteAddr(req *http.Request) Network {
	// This will only be defined when site is accessed via non-anonymous proxy
	// and takes precedence over RemoteAddr
	// Header.Get is case-insensitive
	ipHeader := req.Header.Get("X-Forwarded-For")
	if len(ipHeader) == 0 {
		ipHeader = req.RemoteAddr
	}

	ip, port, err := net.SplitHostPort(ipHeader)
	portNumber, _ := strconv.Atoi(port)
	if err == nil {
		return Network{
			Client: Client{
				IP:   ip,
				Port: portNumber,
			},
		}
	}

	userIP := net.ParseIP(ipHeader)
	if userIP == nil {
		return Network{
			Client: Client{
				IP:   ipHeader,
				Port: portNumber,
			},
		}
	}

	return Network{
		Client: Client{
			IP:   userIP.String(),
			Port: portNumber,
		},
	}
}

func (jwtPlugin *JwtPlugin) VerifyToken(jwtToken *JWT) error {
	for _, h := range jwtToken.Header.Crit {
		if _, ok := supportedHeaderNames[h]; !ok {
			return fmt.Errorf("unsupported header: %s", h)
		}
	}
	// Look up the algorithm
	a, ok := tokenAlgorithms[jwtToken.Header.Alg]
	if !ok {
		return fmt.Errorf("unknown JWS algorithm: %s", jwtToken.Header.Alg)
	}
	if jwtPlugin.alg != "" && jwtToken.Header.Alg != jwtPlugin.alg {
		return fmt.Errorf("incorrect alg, expected %s got %s", jwtPlugin.alg, jwtToken.Header.Alg)
	}
	key, ok := jwtPlugin.keys[jwtToken.Header.Kid]
	if ok {
		return a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
	} else {
		for _, key := range jwtPlugin.keys {
			err := a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("token validation failed")
	}
}

func (jwtPlugin *JwtPlugin) CheckOpa(request *http.Request, token *JWT) error {
	opaPayload, err := toOPAPayload(request)
	if err != nil {
		return err
	}
	if token != nil {
		opaPayload.Input.JWTHeader = token.Header
		opaPayload.Input.JWTPayload = token.Payload
	}
	authPayloadAsJSON, err := json.Marshal(opaPayload)
	if err != nil {
		return err
	}
	authResponse, err := http.Post(jwtPlugin.opaUrl, "application/json", bytes.NewBuffer(authPayloadAsJSON))
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(authResponse.Body)
	if err != nil {
		return err
	}
	var result Response
	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}
	if len(result.Result) == 0 {
		return fmt.Errorf("OPA result invalid")
	}
	fieldResult, ok := result.Result[jwtPlugin.opaAllowField]
	if !ok {
		return fmt.Errorf("OPA result missing: %v", jwtPlugin.opaAllowField)
	}
	var allow bool
	if err = json.Unmarshal(fieldResult, &allow); err != nil {
		return err
	}
	if !allow {
		return fmt.Errorf("%s", body)
	}
	for k, v := range jwtPlugin.opaHeaders {
		var value string
		if err = json.Unmarshal(result.Result[v], &value); err == nil {
			request.Header.Add(k, value) // add OPA result as an HTTP header
		}
	}
	return nil
}

func (jwtPlugin *JwtPlugin) ForwardError(rw http.ResponseWriter, msg string, statusCode int, origReq *http.Request) {
	rw.Header().Set(jwtPlugin.forwardAuthErrorHeader, msg)
	origReq.Header.Set(jwtPlugin.forwardAuthErrorHeader, msg)
	rw.WriteHeader(statusCode)
	jwtPlugin.next.ServeHTTP(rw, origReq)
}


func toOPAPayload(request *http.Request) (*Payload, error) {
	input := &PayloadInput{
		Host:       request.Host,
		Method:     request.Method,
		Path:       strings.Split(request.URL.Path, "/")[1:],
		Parameters: request.URL.Query(),
		Headers:    request.Header,
	}
	contentType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err == nil {
		var save []byte
		save, request.Body, err = drainBody(request.Body)
		if err == nil {
			if contentType == "application/json" {
				err = json.Unmarshal(save, &input.Body)
				if err != nil {
					return nil, err
				}
			} else if contentType == "application/x-www-url-formencoded" {
				input.Form, err = url.ParseQuery(string(save))
				if err != nil {
					return nil, err
				}
			} else if contentType == "multipart/form-data" || contentType == "multipart/mixed" {
				boundary := params["boundary"]
				mr := multipart.NewReader(bytes.NewReader(save), boundary)
				f, err := mr.ReadForm(32 << 20)
				if err != nil {
					return nil, err
				}

				input.Form = make(url.Values)
				for k, v := range f.Value {
					input.Form[k] = append(input.Form[k], v...)
				}
			}
		}
	}
	return &Payload{Input: input}, nil
}

func drainBody(b io.ReadCloser) ([]byte, io.ReadCloser, error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, http.NoBody, nil
	}
	body, err := ioutil.ReadAll(b)
	if err != nil {
		return nil, b, err
	}
	return body, NopCloser(bytes.NewReader(body), b), nil
}

func NopCloser(r io.Reader, c io.Closer) io.ReadCloser {
	return nopCloser{r: r, c: c}
}

type nopCloser struct {
	r io.Reader
	c io.Closer
}

func (n nopCloser) Read(b []byte) (int, error) { return n.r.Read(b) }
func (n nopCloser) Close() error               { return n.c.Close() }

type tokenVerifyFunction func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error
type tokenVerifyAsymmetricFunction func(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error

// jwtAlgorithm describes a JWS 'alg' value
type tokenAlgorithm struct {
	hash   crypto.Hash
	verify tokenVerifyFunction
}

// tokenAlgorithms is the known JWT algorithms
var tokenAlgorithms = map[string]tokenAlgorithm{
	"RS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPKCS)},
	"RS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPKCS)},
	"RS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPKCS)},
	"PS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPSS)},
	"PS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPSS)},
	"PS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPSS)},
	"ES256": {crypto.SHA256, verifyAsymmetric(verifyECDSA)},
	"ES384": {crypto.SHA384, verifyAsymmetric(verifyECDSA)},
	"ES512": {crypto.SHA512, verifyAsymmetric(verifyECDSA)},
	"HS256": {crypto.SHA256, verifyHMAC},
	"HS384": {crypto.SHA384, verifyHMAC},
	"HS512": {crypto.SHA512, verifyHMAC},
}

// errSignatureNotVerified is returned when a signature cannot be verified.
func verifyHMAC(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
	macKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("incorrect symmetric key type")
	}
	mac := hmac.New(hash.New, macKey)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	sum := mac.Sum([]byte{})
	if !hmac.Equal(signature, sum) {
		return fmt.Errorf("token verification failed (HMAC)")
	}
	return nil
}

func verifyAsymmetric(verify tokenVerifyAsymmetricFunction) tokenVerifyFunction {
	return func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa := key.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(publicKeyRsa, hash, digest, signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS)")
	}
	return nil
}

func verifyRSAPSS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	if err := rsa.VerifyPSS(publicKeyRsa, hash, digest, signature, nil); err != nil {
		return fmt.Errorf("token verification failed (RSAPSS)")
	}
	return nil
}

func verifyECDSA(key interface{}, _ crypto.Hash, digest []byte, signature []byte) error {
	publicKeyEcdsa, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	r, s := &big.Int{}, &big.Int{}
	n := len(signature) / 2
	r.SetBytes(signature[:n])
	s.SetBytes(signature[n:])
	if ecdsa.Verify(publicKeyEcdsa, digest, r, s) {
		return nil
	}
	return fmt.Errorf("token verification failed (ECDSA)")
}

// JWKThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(jwk string) (string, error) {
	bs := sha256.Sum256([]byte(jwk))
	bytesArr := []byte{}
	for i := range bs {
		bytesArr = append(bytesArr, bs[i])
	}
	return base64.RawURLEncoding.EncodeToString(bytesArr), nil
}
