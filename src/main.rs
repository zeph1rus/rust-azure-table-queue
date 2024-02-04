use queuemsg;


#[tokio::main]
async fn main() {
    queuemsg::create_request("I'm an example request".to_string()).await;


}