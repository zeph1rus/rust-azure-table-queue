use std::fmt::Error;
use chrono::{Local, DateTime};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use base64::{Engine as _, engine::general_purpose};

static STORAGE_ACCOUNT_NAME: &'static str = "my-storage-account-name";
static STORAGE_ACCOUNT_KEY: &'static str = "STORAGE_ACCOUNT_KEY";
static QUEUE_NAME:  &'static str = "queue_name";
static QUEUE_URL:  &'static str = "https://my-storage-account-name.queue.core.windows.net/queue_name/messages";
static X_MS_VERSION: &'static str = "2011-08-18";


/// we can't use chrono's `%Z` format here as the api does not allow UTC as a timezone.
/// I hardcode it to GMT but switch your timezone about as you see fit, it will throw an 'invalid time' response
/// if it doesn't like the format.  The format is allegedly RFC1123 but the documentation for the dotnet parser
/// which I assume is what is being used suggests their format is only 'based' on it.
/// https://learn.microsoft.com/en-us/dotnet/api/system.globalization.datetimeformatinfo.rfc1123pattern?view=net-8.0
///
fn format_date_str(dt: DateTime<Local>) -> String {
    format!("{}", dt.format("%a, %d %b %Y %H:%M:%S GMT"))
}

/// the canonicalized_headers string just contains all the header values pre-pended with 'x-ms-' stuffed in the signature
/// this is because they are matched with the values in the actual request.  For queues we only pass two so it's just a simple
/// format string.
/// if you have more headers the method in the unofficial azure rust sdk is going to be more sane:
/// https://github.com/Azure/azure-sdk-for-rust/blob/ddedf470b09c1b1ce8a7dc050aded67211b5519b/sdk/storage/src/authorization/authorization_policy.rs#L155
///
fn canonical_headers(date_time: String) -> String {
    // Time Format: "Sun, 02 Sep 2009 20:36:40 GMT"
    // this is RFC1123 "%a, %d %b %Y %H:%M:%S %Z"
    // https://docs.rs/chrono_parser/latest/chrono_parser/formats/constant.RFC1123.html
    format!("x-ms-date:{}\nx-ms-version:{}", date_time, X_MS_VERSION)
}

/// construct the canonicalized_resource string according to the documentation at:
/// https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string
/// note: for queues you have to append the /messages endpoint despite the documentation not suggesting that at all.
fn canonical_resource() -> String {
    let mut cr_string = Vec::<String>::new();
    cr_string.push("/".to_string());
    cr_string.push(STORAGE_ACCOUNT_NAME.to_string());
    cr_string.push("/".to_string());
    cr_string.push(QUEUE_NAME.to_string());
    cr_string.push("/messages".to_string());
    cr_string.join("")
}

/// construct_signature makes the following signature string.
/// of note - only Content-Length is acutally parsed for queue service
/// Date is optional - but you have to provide x-ms-date in the signature and the request regardless
/// so it's basically not required.
///
/// StringToSign = VERB + "\n" +
///                Content-Encoding + "\n" +
///                Content-Language + "\n" +
///                Content-Length + "\n" +
///                Content-MD5 + "\n" +
///                Content-Type + "\n" +
///                Date + "\n" +
///                If-Modified-Since + "\n" +
///                If-Match + "\n" +
///                If-None-Match + "\n" +
///                If-Unmodified-Since + "\n" +
///                Range + "\n" +
///                CanonicalizedHeaders +
///                CanonicalizedResource;
fn construct_signature(content_length: usize, date_time: String) -> String {
    let mut auth_string = Vec::<String>::new();
    //verb
    auth_string.push(String::from("POST\n"));
    //content encoding
    auth_string.push(String::from("\n"));
    //content language
    auth_string.push(String::from("\n"));
    //content length. Must be nothing if 0
    match content_length {
        0 => auth_string.push(String::from("\n")),
        _ => auth_string.push(format!("{}\n", content_length))
    }
    // content-md5
    auth_string.push(String::from("\n"));
    //content-type (this _should_ be empty i think)
    auth_string.push(String::from("\n"));
    //Date
    auth_string.push(String::from("\n"));
    // if-modified
    auth_string.push(String::from("\n"));
    // if match
    auth_string.push(String::from("\n"));
    // if none match
    auth_string.push(String::from("\n"));
    // if unmodified since
    auth_string.push(String::from("\n"));
    // range
    auth_string.push(String::from("\n"));

    let canonicalised_headers = canonical_headers(date_time);
    auth_string.push(canonicalised_headers);
    auth_string.push(String::from("\n"));

    let canonicalised_resource = canonical_resource();
    auth_string.push(canonicalised_resource);

    auth_string.join("")
}

/// the queue message is actually XML (no, I don't know why when every other azure service consumes JSON)
/// The XML format is simple and static so we construct it manually rather than using `serde_xml_rs` or another
/// sane XML parsing crate.
fn create_content_string(contents: String) -> String {
    let mut content_string = Vec::<String>::new();
    content_string.push("<QueueMessage>\n".to_string());
    content_string.push(format!("<MessageText>{}</MessageText>\n", contents));
    content_string.push("</QueueMessage>".to_string());
    content_string.join("")
}

/// construct the signed signature string
/// Azure decrypts this with the shared key then compares the contents to
/// it's computed version of the request details.  If they match it's
/// considered to be authorized
fn hmac_256(data: &str, secret: &str) -> Result<String, Error> {
    // this is the new format for base64::decode - old way is deprecated
    let key = general_purpose::STANDARD.decode(secret);
    match key {
        Ok(decoded) => {
            let hmac = Hmac::<Sha256>::new_from_slice(&decoded);
            match hmac {
                Ok(mut hm256) => {
                    hm256.update(data.as_bytes());
                    let sig = hm256.finalize().into_bytes();
                    Ok(general_purpose::STANDARD.encode(sig))
                }
                Err(e) => {
                    // we can't do anything if we can't encrypt the sig, so panic
                    // hopefully with a useful error
                    panic!("Couldn't Create hmac instance{:?}",  e);
                }
            }

        }
        Err(_) => panic!("Couldn't Decode account key to base64")
    }

}


pub async fn create_request(message_text: String) {

    let body_content = create_content_string(message_text);

    // you may have to mess with this depending on your timezone.
    // it may be easiest to just generate utc and pretend it's GMT. see notes on this function for
    // silliness
    let dt = format_date_str(Local::now());

    // cloning dt is lazy but we only do it once and none of this has a long lifetime.
    let auth_str=construct_signature(body_content.len(), dt.clone());

    // we panic if this doesn't work so should be ok to just unwrap this.
    let encoded_auth = hmac_256(auth_str.as_str(), STORAGE_ACCOUNT_KEY).unwrap();

    let auth_header = format!("SharedKey {}:{}", STORAGE_ACCOUNT_NAME, encoded_auth);

    let client = reqwest::Client::new();
    let response = client
        .post(QUEUE_URL)
        .header("x-ms-date", dt)
        .header("x-ms-version", X_MS_VERSION)
        .header("Authorization", auth_header)
        .header("Content-Length", body_content.len())
        .body(body_content) // if you forget this your request will hang indefinitely. Yes it took a while to figure that i'd missed this.
        .send()
        .await
        .unwrap();
        // OK is 201 in azure. thanks azure.
        match response.status().is_success() {
         true => {
            let headers = response.headers().to_owned();
            let  body = response.bytes().await.unwrap();
            println!("Successful Request!\nResponse Text: {:?} \nHeaders: {:?}", body, headers)
        }
        _ => {
            let status = response.status();
            println!("{:?}", status);
            let headers = response.headers().to_owned();
            let  body = response.bytes().await.unwrap();
            println!("Response Text: {:?} \n Headers: {:?}", body, headers);
        }
    }
}
