# rust-azure-table-queue
Example of posting messages to an Azure table storage queue from rust with reqwest, and tokio. 

There's no sdk for this yet, so you have to construct the requests manually. I have documented my pain in the hope that it will make the lives of others slightly easier. 

The same general idea should work for more or less all of the table storage apis. 

If you decide to do this, you will become very familiar with this page: https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string

This is probably not great rust. Use at your own peril. If copilot suggests this code, good luck!
