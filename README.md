This is a tool to create an API gateway, its authentication and API portal instantaneously. Just create an openapi.yaml and use it to generate all the infrastructure to activate it using terraform 

## Getting Started

First, create an openapi spec for your API, hit the Generate terraform script button, download the zip file and unzip. In that directory

```bash
chmod +x *.sh
# then
./terraform-[the name of your api] [AWS_CLIENT_ID] [AWS_SECRET] [AWS_REGION] [EMAIL]

Then open the resulting API dev portal URL in your browser and use the login and password provided to authenticate.
