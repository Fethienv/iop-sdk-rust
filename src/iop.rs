// #![warn(dead_code)]
// #![warn(unused_assignments)]
// #![warn(unused_imports)]
// #![warn(private_in_public)]

use itertools::Itertools;
use std::collections::HashMap;
use std::time::SystemTime;
use std::fmt::Display;

use reqwest::{ClientBuilder, Result, header::{HeaderValue, USER_AGENT, CONTENT_TYPE, CACHE_CONTROL, CONNECTION}};
use std::time::Duration;

use md5::{Md5, Digest};
use hmac::{Hmac, Mac};

//use ring::{digest, hmac};
//use data_encoding::BASE64;

// Create alias for HMAC-SHA256
type HmacMd5 = Hmac<Md5>;

const SIGN_METHOD_SHA256:&str = "sha256";
const SIGN_METHOD_MD5:&str    = "md5";
const SIGN_METHOD_HMAC:&str   = "hmac";

const SYSTEM_GENERATE_VERSION:&str = "iop-sdk-rust-20231210";

const P_APPKEY:&str       = "app_key";
const P_API:&str          = "method";
const P_METHOD:&str       = "method";
const P_SESSION:&str      = "session";
const P_ACCESS_TOKEN:&str = "access_token";
const P_VERSION:&str      = "v";
const P_FORMAT:&str       = "format";
const P_TIMESTAMP:&str    = "timestamp";
const P_SIGN:&str         = "sign";
const P_SIGN_METHOD:&str  = "sign_method";
const P_PARTNER_ID:&str   = "partner_id";
const P_DEBUG:&str        = "debug";
const P_SIMPLIFY:&str     = "simplify";

const P_CODE:&str         = "code";
const P_TYPE:&str         = "type";
const P_MESSAGE:&str      = "message";
const P_REQUEST_ID:&str   = "request_id";

const N_REST:&str         = "/rest";
const N_SYNC:&str         = "/sync";

// const P_API_GATEWAY_URL_TW:&str = 'https://api.taobao.tw/rest'
// const P_API_AUTHORIZATION_URL:&str = 'https://auth.taobao.tw/rest'

const GENERATE_SECURITY_TOKEN_URL:&str = "/auth/token/security/create";
const GENERATE_TOKEN_URL:&str          = "/auth/token/create";
const REFRESH_SECURITY_TOKEN_URL:&str  = "/auth/token/security/refresh";
const REFRESH_TOKEN_URL:&str           = "/auth/token/refresh";

const P_LOG_LEVEL_DEBUG:&str = "DEBUG";
const P_LOG_LEVEL_INFO:&str  = "INFO";
const P_LOG_LEVEL_ERROR:&str = "ERROR";

pub type RequestParameters = HashMap<String, String>;

#[derive(PartialEq)]
pub enum SignMethod {
    Md5,
    HmacMd5,
    HmacSha256,
}

impl Display for SignMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use SignMethod::*;
        match &self {
            Md5        => "md5", 
            HmacMd5    => "md5", 
            HmacSha256 => "sha256", 
        }
        .fmt(f)
    }
}

enum HttpMethod {
    Post,
    Get,
    Update,
    Put,
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use HttpMethod::*;
        match &self {
            Post   => "post", 
            Get    => "get", 
            Update => "update", 
            Put    => "put", 
        }
        .fmt(f)
    }
}

pub enum DevicesIds {
    Adid,//adid: Android
    Afai,//afai: Amazon
    Idfa,//idfa: Apple phones (iOS)
    Lgudid,//lgudid: LG
    Msai, //msai: Xbox
    Rida, //rida: Roku
    Tifa, //tifa: Samsung
    TvOS, //tvOS: AppleTV (tvOS)
    Vaid, //vaid: VIDAA OS
    Vida, //vida: Vizio
}

impl Display for DevicesIds {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use DevicesIds::*;
        match &self {
            Adid   => "adid",  // Android
            Afai   => "afai",  // Amazon
            Idfa   => "idfa",  // Apple phones (iOS)
            Lgudid => "lgudid",// LG
            Msai   => "msai",  // Xbox
            Rida   => "rida",  // Roku
            Tifa   => "tifa",  // Samsung
            TvOS   => "tvOS",  // AppleTV (tvOS)
            Vaid   => "vaid",  // VIDAA OS
            Vida   => "vida",  // Vizio
        }
        .fmt(f)
    }
}

#[derive(PartialEq)]
enum RequestType {
    System,
    Business
}

pub enum ApiName {

    // System
    GenerateSecurityToken,    // /auth/token/security/create
    GenerateToken,            // /auth/token/create
    RefreshSecurityToken,     // /auth/token/security/refresh
    RefreshToken,             // /auth/token/refresh

    // AE-Affiliate
    GenerateAffiliateLinks,   // aliexpress.affiliate.link.generate
    GetCategory,              // aliexpress.affiliate.category.get
    GetFeaturedPromoInfo,     // aliexpress.affiliate.featuredpromo.get
    GetFeaturedPromoProducts, // aliexpress.affiliate.featuredpromo.products.get
    GetHotProductDownload,    // aliexpress.affiliate.hotproduct.download
    GetHotProducts,           // aliexpress.affiliate.hotproduct.query
    GetOrderInfo,             // aliexpress.affiliate.order.get
    GetOrderList,             // aliexpress.affiliate.order.list
    GetOrderListByIndex,      // aliexpress.affiliate.order.listbyindex
    GetProductDetailInfo,     // aliexpress.affiliate.productdetail.get
    GetProducts,              // aliexpress.affiliate.product.query
    SmartMatchProducts        // aliexpress.affiliate.product.smartmatch
    
}

impl ApiName {
    fn get_request_type(&self) -> RequestType{
        use ApiName::*;
        match self {
            GenerateSecurityToken | 
            GenerateToken         | 
            RefreshSecurityToken  | 
            RefreshToken          =>  RequestType::System, 
            _                     =>  RequestType::Business, 
        }
    }
}

impl Display for ApiName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ApiName::*;
        match &self {
            // System
            GenerateSecurityToken    => "/auth/token/security/create",
            GenerateToken            => "/auth/token/create",
            RefreshSecurityToken     => "/auth/token/security/refresh",
            RefreshToken             => "/auth/token/refresh",

            // AE-Affiliate
            GenerateAffiliateLinks   => "aliexpress.affiliate.link.generate",
            GetCategory              => "aliexpress.affiliate.category.get",
            GetFeaturedPromoInfo     => "aliexpress.affiliate.featuredpromo.get",
            GetFeaturedPromoProducts => "aliexpress.affiliate.featuredpromo.products.get",
            GetHotProductDownload    => "aliexpress.affiliate.hotproduct.download",
            GetHotProducts           => "aliexpress.affiliate.hotproduct.query",
            GetOrderInfo             => "aliexpress.affiliate.order.get",
            GetOrderList             => "aliexpress.affiliate.order.list",
            GetOrderListByIndex      => "aliexpress.affiliate.order.listbyindex",
            GetProductDetailInfo     => "aliexpress.affiliate.productdetail.get",
            GetProducts              => "aliexpress.affiliate.product.query",
            SmartMatchProducts       => "aliexpress.affiliate.product.smartmatch"
        }
        .fmt(f)
    }
}

pub struct Iop{
    app_key:String,
    secret:String,
    business_domain:String,
    system_domain:String,
    port  :u32,
    httpmethod:HttpMethod,
    api_name: String
}

impl Iop{

    pub fn new(app_key:&str, secret:&str) -> Self{
        Iop{
            app_key: app_key.to_string(),
            secret: secret.to_string(),
            business_domain: String::from("api-sg.aliexpress.com"),	
            system_domain: String::from("api-sg.aliexpress.com"),	
            port: 443,
            httpmethod: HttpMethod::Get,
            api_name: ApiName::GetFeaturedPromoInfo.to_string()
        }
    }

    pub fn set_app_info(mut self, app_key:&str, secret:&str){
        self.app_key = app_key.to_string();
        self.secret = secret.to_string();
    }

    pub fn set_business_domain(mut self, business_domain:&str){
        self.business_domain = business_domain.to_string();
    }

    pub fn set_system_domain(mut self, system_domain:&str){
        self.system_domain = system_domain.to_string();
    }

    pub fn set_port(mut self, port:u32){
        self.port = port;
    }

    pub fn set_httpmethod(mut self, httpmethod: HttpMethod){
        self.httpmethod = httpmethod;
    }

    pub fn set_api_name(&mut self, api_name:&str){
        self.api_name = api_name.to_string();
    }

    pub fn get_api_name(&self) -> &str{
        &self.api_name  
    }

    pub async fn generate_security_token(&self, code:String, uuid: String) -> Result<reqwest::Response>{
        let mut request_parameters: RequestParameters = HashMap::new();

        request_parameters.insert("code".to_string(), code);
        request_parameters.insert("uuid".to_string(), uuid);

        let response = self.request(ApiName::GenerateSecurityToken, Some(request_parameters)).await;
        
        response
    }

    pub async fn generate_token(&self, code:String, uuid: String) -> Result<reqwest::Response>{
        let mut request_parameters:RequestParameters = HashMap::new();

        request_parameters.insert("code".to_string(), code);
        request_parameters.insert("uuid".to_string(), uuid);

        let response = self.request(ApiName::GenerateToken, Some(request_parameters)).await;
        
        response
    }

    pub async fn refresh_security_token(&self, refresh_token:String) -> Result<reqwest::Response>{
        let mut request_parameters:RequestParameters = HashMap::new();
        request_parameters.insert("refresh_token".to_string(), refresh_token);
        let response = self.request(ApiName::RefreshSecurityToken, Some(request_parameters)).await;
        response
    }

    pub async fn refresh_token(&self, refresh_token:String)-> Result<reqwest::Response>{
        let mut request_parameters:RequestParameters = HashMap::new();
        request_parameters.insert("refresh_token".to_string(), refresh_token);
        let response = self.request(ApiName::RefreshToken, Some(request_parameters)).await;
        response
    }
   
    pub async fn request(&self, api: ApiName, request_parameters: Option<RequestParameters>) -> Result<reqwest::Response> {

        let mut base_url = String::new();

        if self.port == 443 {
            base_url.push_str("https://"); 
        }else{
            base_url.push_str("http://");     
        }
        
        if api.get_request_type() == RequestType::System {
            base_url.push_str(self.system_domain.as_str());
            base_url.push_str(N_REST);
            base_url.push_str(api.to_string().as_str());

        }else{ //RequestType::Business
            base_url.push_str(self.business_domain.as_str());
            base_url.push_str(N_SYNC);
        }

        base_url.push_str("?");

        let parameters = self.make_parameters(api, None, request_parameters);

        let request_url = self.generate_request_url(base_url, parameters);

        //println!("{:?}", &request_url);
        
        // TODO: 1. Fix Post method
        // TODO: 2. Add more methods
        match self.httpmethod {
            HttpMethod::Post => Self::make_post_request(request_url.as_str(), "").await,
            _ => Self::make_get_request(request_url.as_str()).await 
        }
    }

    fn generate_request_url(&self, base_url:String, parameters:RequestParameters) -> String{
        
        let mut request_url = base_url;

        for (index, (key, value)) in parameters.iter().sorted().enumerate(){
            if !value.is_empty(){
                request_url.push_str(format!("{key}={value}").as_str());
                if index < parameters.len()-1{
                    request_url.push_str("&");  
                }
            }
        }

        request_url
    }

    fn make_parameters(&self, api: ApiName, authrize:Option<String>, request_parameters: Option<RequestParameters>) -> RequestParameters{

        let dt = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        let timestamp = dt.as_nanos()/1000000;
        
        let mut sys_parameters:HashMap<String, String> = HashMap::new();

        sys_parameters.insert(P_FORMAT.to_string(),     String::from("json"));
        sys_parameters.insert(P_APPKEY.to_string(),     (&self.app_key).to_string());
        sys_parameters.insert(P_SIGN_METHOD.to_string(),String::from("md5"));
        sys_parameters.insert(P_VERSION.to_string(),    String::from("2.0"));
        sys_parameters.insert(P_TIMESTAMP.to_string(),  timestamp.to_string());
        sys_parameters.insert(P_PARTNER_ID.to_string(), String::from(SYSTEM_GENERATE_VERSION));
        
        if api.get_request_type() == RequestType::Business {
            sys_parameters.insert(P_API.to_string(),api.to_string());
        }

        if let Some(aut) = authrize {
            sys_parameters.insert(P_SESSION.to_string(), aut);
        }

        if let Some(req_parameters) = request_parameters{
            sys_parameters.extend(req_parameters.into_iter());
        }
        
        let sign = Self::sign(self.secret.as_str(), sys_parameters.clone(), "md5");

        sys_parameters.insert(P_SIGN.to_string(), sign);

        sys_parameters
    
    }

    async fn make_get_request(url: &str) -> Result<reqwest::Response> {
        let timeout = Duration::new(10, 0);
        let client = ClientBuilder::new().timeout(timeout).build()?;
        let response: reqwest::Response = client
            .get(url)
            .header(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.99 Mobile/15E148 Safari/604.1"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8")
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "Keep-Alive")
            .send()
            .await?;
          
        Ok(response) 
    }

    async fn make_post_request(url: &str, body:&str) -> Result<reqwest::Response> {
        let timeout = Duration::new(10, 0);
        let client = ClientBuilder::new().timeout(timeout).build()?;
        let response: reqwest::Response = client
            .post(url)
            .header(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.99 Mobile/15E148 Safari/604.1"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8")
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "Keep-Alive")
            .body(body.to_string()) // TODO: repaire this
            .send()
            .await?;
          
        Ok(response) 
    }

    pub fn sign(secret:&str, params:RequestParameters, sign_method: &str) -> String{
        //Step 1: Check whether parameters have been sorted.
        // let keys:Vec<String> = params.keys();
        // keys.sort();
    
        //Step 2: Splice all sorted parameter names and values together.
        let mut query = String::new();
        if SIGN_METHOD_MD5 == sign_method{
            query.push_str(secret);
        }
    
        for (key, value) in params.iter().sorted(){
            if !key.is_empty() && !value.is_empty(){
                query.push_str(key.as_str());
                query.push_str(value.as_str());
            }
        }
    
        let mut bytes: Vec<u8> = Vec::new();
    
        //Step 3: Use the MD5 or HMAC_MD5 algorithm to encrypt the spliced character string.
        if SIGN_METHOD_HMAC == sign_method {
            bytes = Self::encrypt_hmac(query.as_str(), secret);
        } else {
            query.push_str(secret);
            bytes = Self::encrypt_md5(query.as_str());
        }
    
        //Step 4: Convert binary characters into capitalized hexadecimal characters. (A correct signature must be a character string consisting of 32 capitalized hexadecimal characters. This step is performed as required.)
        let hex = Self::byte2hex(bytes);
        
        hex.to_uppercase()
    }
    
    //TODO: switch between h265 and md5
    fn encrypt_hmac(data:&str, secret:&str) -> Vec<u8> {
        let mut mac = HmacMd5::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        let result = mac.finalize();
    
        let bytes = result.into_bytes();
    
        bytes[..].to_vec()
    }
    
    fn encrypt_md5(data:&str) -> Vec<u8>{
        let mut hasher = Md5::new();
    
        // process input message
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        result[..].to_vec()
    }
    
    fn byte2hex(bytes: Vec<u8>) -> String {
        let hex : String = bytes.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("");
        hex
    }
        
}
