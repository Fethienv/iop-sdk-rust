# iop-sdk-rust
Unofficial Rust AliExpress Open platform SDK (iop-sdk-rust)


## Example:

```

use dotenv_vault::dotenv;
use reqwest::Result;
use std::collections::HashMap;

mod iop;
use iop::{Iop, ApiName, RequestParameters};


#[tokio::main]
async fn main() -> Result<()> {

    dotenv().expect(".env file not found");

    let app_key = std::env::var("APPKEY").expect("APPKEY variable dosn't exist");
    let secret = std::env::var("SECRET").expect("SECRET variable dosn't exist");

    let top_api = Iop::new(app_key.as_str(), secret.as_str());

    let mut request_parameters: RequestParameters = HashMap::new();
    request_parameters.insert("app_signature".to_string(), "asdasdasdsa".to_string());
    
    let response = top_api.request(ApiName::GetCategory, Some(request_parameters)).await?;

    if response.status().is_success(){
        println!("is_success"); 
        println!("{:#?}", response.text().await?);  
    }

    Ok(())
}

```