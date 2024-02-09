import json
from datetime import datetime, timedelta
import asyncio
import httpx

class PolestarAuthException(Exception):
    """Exception raised for authentication errors."""

    def __init__(self, message, status_code):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class PolestarAuthenticator:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.resume_path = None
        self.code = None
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self._client_session = httpx.AsyncClient()  # Initialize HTTPX client session

    async def get_resume_path(self):
        params = {
            "response_type": "code",
            "client_id": "polmystar",
            "redirect_uri": "https://www.polestar.com/sign-in-callback"
        }
        response = await self._client_session.get("https://polestarid.eu.polestar.com/as/authorization.oauth2", params=params)
        
        if response.status_code == 303:
            location_header = response.headers.get('Location')
            if location_header:
                query_params = location_header.split('?')[1]
                resume_path = query_params.split('&')[0].split('=')[1]
                return resume_path
            else:
                raise Exception("Location header not found in the response")
        else:
            raise Exception(f"Error getting resume path, unexpected status code: {response.status_code}")

    async def _get_code(self) -> None:
        self.resume_path = await self.get_resume_path()

        # get the resumePath
        if self.resume_path:
            resumePath = self.resume_path

            params = {
                'client_id': 'polmystar'
            }
            data = {
                'pf.username': self.username,
                'pf.pass': self.password
            }
            result = await self._client_session.post(
                f"https://polestarid.eu.polestar.com/as/{resumePath}/resume/as/authorization.ping",
                params=params,
                data=data
            )
            self.latest_call_code = result.status_code
            
            if result.status_code == 302:  # Check for the desired status code
                # Extract code from the redirection URL
                location_header = result.headers.get('Location')
                if location_header:
                    self.code = location_header.split('?')[1].split('&')[0].split('=')[1]
                    #return code
                else:
                    raise PolestarAuthException("Code not found in redirection URL", result.status_code)
            else:
                raise PolestarAuthException("Error getting code", result.status_code)


    async def get_token(self):  # Change get_token method to async
        if self.code:
            params = {
                "query": "query getAuthToken($code: String!) { getAuthToken(code: $code) { access_token refresh_token expires_in }}",
                "operationName": "getAuthToken",
                "variables": json.dumps({"code": self.code})
            }
            headers = {"Content-Type": "application/json"}
            response = await self._client_session.get("https://pc-api.polestar.com/eu-north-1/auth/", params=params, headers=headers)
            if response.status_code == 200:
                token_data = response.json()['data']['getAuthToken']
                self.access_token = token_data['access_token']
                self.refresh_token = token_data['refresh_token']
                self.token_expiry = datetime.now() + timedelta(seconds=token_data['expires_in'])
            else:
                raise Exception("Error getting token")


async def main():
    username = "your_user"
    password = "your_pass"
    authenticator = PolestarAuthenticator(username, password)
    await authenticator._get_code()
    await authenticator.get_token()
    print("Access Token:", authenticator.access_token)

# Run the main function synchronously
asyncio.run(main())
