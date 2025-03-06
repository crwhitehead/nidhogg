# nidhogg/core/network_interceptor.py
import socket
import ssl
import urllib.request
import http.client
import requests
import io
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from crosshair.tracers import PatchingModule, COMPOSITE_TRACER
from nidhogg.utils.debug import debug

@dataclass
class NetworkRequest:
    """Information about an intercepted network request"""
    url: str
    method: str = "GET"
    data: Optional[bytes] = None
    headers: Dict[str, str] = field(default_factory=dict)
    source_file: str = ""
    source_line: int = 0

@dataclass
class HttpResponse:
    """A simulated HTTP response"""
    status_code: int = 200
    content: bytes = b''
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {'Content-Type': 'application/json'}
    
    def json(self):
        """Convert response content to JSON, similar to requests"""
        return json.loads(self.content)
    
    def read(self):
        """Mimic file-like interface for urllib responses"""
        return self.content

    def close(self):
        """No-op close method"""
        pass

class NetworkInterceptor:
    """
    Intercepts network function calls and records them for security analysis in Nidhogg.
    
    This class uses CrossHair's patching mechanism to replace network-related 
    functions with safe simulations that don't actually make network requests.
    """
    
    def __init__(self):
        self.patching_module = None
        self._response_overrides = {}
        self._default_response = HttpResponse(
            status_code=200,
            content=b'{"status": "ok", "simulated": true}',
            headers={'Content-Type': 'application/json'}
        )
        
        # Track intercepted requests for analysis
        self.intercepted_requests: List[NetworkRequest] = []
        
        # Set up default patches for common network functions
        self._patches = {
            # Socket-related functions
            socket.socket: self._mock_socket,
            
            # urllib.request functions
            urllib.request.urlopen: self._mock_urlopen,
            
            # http.client functions
            http.client.HTTPConnection.request: self._mock_http_request,
            http.client.HTTPConnection.getresponse: self._mock_http_getresponse,
            
            # requests library functions
            requests.get: self._mock_requests_get,
            requests.post: self._mock_requests_post,
            requests.put: self._mock_requests_put,
            requests.delete: self._mock_requests_delete,
            requests.patch: self._mock_requests_patch,
            requests.request: self._mock_requests_request,
            
            # SSL-related functions
            ssl.create_default_context: self._mock_ssl_context,
        }
    
    def set_response_for_url(self, url: str, response: HttpResponse) -> None:
        """
        Set a specific response for a given URL.
        
        Args:
            url: The URL to match
            response: The HttpResponse to return when this URL is requested
        """
        self._response_overrides[url] = response
    
    def set_default_response(self, response: HttpResponse) -> None:
        """
        Set the default response for URLs without specific overrides.
        
        Args:
            response: The HttpResponse to use as default
        """
        self._default_response = response
    
    def _get_response_for_url(self, url: str) -> HttpResponse:
        """Get the appropriate response for a URL, using overrides if available"""
        # First, try an exact match
        if url in self._response_overrides:
            return self._response_overrides[url]
        
        # Next, try matching the base URL (without query parameters)
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base_url in self._response_overrides:
            return self._response_overrides[base_url]
        
        # Return the default response
        debug(f"Using default response for URL: {url}")
        return self._default_response
    
    def _record_network_request(self, url: str, method: str = "GET", data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None):
        """
        Record a network request for later security analysis.
        """
        import inspect
        frame = inspect.currentframe()
        source_file = ""
        source_line = 0
        
        # Walk up the call stack until we find a non-framework file
        while frame:
            if not any(x in frame.f_code.co_filename for x in ['network_interceptor.py', 'tracers.py', 'crosshair']):
                source_file = frame.f_code.co_filename
                source_line = frame.f_lineno
                break
            frame = frame.f_back
            
        request = NetworkRequest(
            url=url,
            method=method,
            data=data,
            headers=headers or {},
            source_file=source_file,
            source_line=source_line
        )
        self.intercepted_requests.append(request)
        debug(f"Intercepted network request: {method} {url} from {source_file}:{source_line}")

    # Mock implementations for different network functions
    def _mock_socket(self, *args, **kwargs):
        """Mock socket.socket() calls"""
        class MockSocket:
            def __init__(self, *args, **kwargs):
                pass
            
            def connect(self, addr):
                host, port = addr
                self_outer = self
                self_outer._record_network_request(f"socket://{host}:{port}")
                return None
            
            def connect_ex(self, addr):
                host, port = addr
                self_outer = self
                self_outer._record_network_request(f"socket://{host}:{port}")
                return 0  # Success
            
            def send(self, data):
                return len(data)
                
            def sendall(self, data):
                return None
                
            def recv(self, bufsize):
                return b''
                
            def settimeout(self, timeout):
                pass
                
            def close(self):
                pass
                
            def shutdown(self, how):
                pass
        
        return MockSocket(*args, **kwargs)

    def _mock_urlopen(self, url, data=None, timeout=None, *args, **kwargs):
        """Mock urllib.request.urlopen() calls"""
        url_str = url.full_url if hasattr(url, 'full_url') else url
        
        # Record the request
        self._record_network_request(
            url=url_str,
            method="POST" if data else "GET",
            data=data
        )
        
        response = self._get_response_for_url(url_str)
        
        # Create a file-like object that mimics an HTTP response
        class MockResponse:
            def __init__(self, http_response):
                self.http_response = http_response
                self.status = http_response.status_code
                self._data = http_response.content
                self.headers = self.http_response.headers
                
            def read(self, amt=None):
                if amt is not None:
                    result = self._data[:amt]
                    self._data = self._data[amt:]
                    return result
                else:
                    result = self._data
                    self._data = b''
                    return result
                    
            def close(self):
                pass
                
            def info(self):
                class MockHeaders:
                    def __init__(self, headers):
                        self._headers = headers
                    
                    def get(self, name, default=None):
                        return self._headers.get(name, default)
                    
                    def __getitem__(self, name):
                        return self._headers.get(name)
                
                return MockHeaders(self.http_response.headers)
        
        return MockResponse(response)

    def _mock_http_request(self, self_conn, method, url, body=None, headers=None, **kwargs):
        """Mock http.client.HTTPConnection.request method"""
        full_url = f"http://{self_conn.host}:{self_conn.port}{url}"
        
        # Record the request
        self._record_network_request(
            url=full_url,
            method=method,
            data=body,
            headers=headers
        )
        
        # Store the request info on the connection object for later use in getresponse
        self_conn._mockurl = url
        self_conn._mockmethod = method
        self_conn._mockbody = body
        self_conn._mockheaders = headers
        return None

    def _mock_http_getresponse(self, self_conn, **kwargs):
        """Mock http.client.HTTPConnection.getresponse method"""
        url = getattr(self_conn, '_mockurl', '/')
        full_url = f"http://{self_conn.host}:{self_conn.port}{url}"
        
        response = self._get_response_for_url(full_url)
        
        # Create a response-like object
        class MockHTTPResponse:
            def __init__(self, http_response):
                self.http_response = http_response
                self.status = http_response.status_code
                self.reason = "OK" if self.status == 200 else "Error"
                self._data = http_response.content
                
            def read(self, amt=None):
                if amt is not None:
                    result = self._data[:amt]
                    self._data = self._data[amt:]
                    return result
                else:
                    result = self._data
                    self._data = b''
                    return result
                    
            def close(self):
                pass
                
            def getheader(self, name, default=None):
                return self.http_response.headers.get(name, default)
                
            def getheaders(self):
                return list(self.http_response.headers.items())
        
        return MockHTTPResponse(response)

    def _mock_requests_request(self, method, url, **kwargs):
        """Mock requests.request method"""
        # Record the request
        self._record_network_request(
            url=url,
            method=method,
            data=kwargs.get('data') or (json.dumps(kwargs.get('json')).encode() if kwargs.get('json') else None),
            headers=kwargs.get('headers')
        )
        
        response = self._get_response_for_url(url)
        
        # Create a requests.Response-like object
        class MockRequestsResponse:
            def __init__(self, http_response):
                self.http_response = http_response
                self.status_code = http_response.status_code
                self._content = http_response.content
                self.headers = http_response.headers
                self.url = url
                self.request = kwargs
                
            @property
            def content(self):
                return self._content
                
            def json(self):
                return json.loads(self._content)
                
            @property
            def text(self):
                return self._content.decode('utf-8')
                
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise requests.HTTPError(f"HTTP Error {self.status_code}")
        
        return MockRequestsResponse(response)
        
    def _mock_requests_get(self, url, **kwargs):
        """Mock requests.get method"""
        return self._mock_requests_request('GET', url, **kwargs)
        
    def _mock_requests_post(self, url, **kwargs):
        """Mock requests.post method"""
        return self._mock_requests_request('POST', url, **kwargs)
        
    def _mock_requests_put(self, url, **kwargs):
        """Mock requests.put method"""
        return self._mock_requests_request('PUT', url, **kwargs)
        
    def _mock_requests_delete(self, url, **kwargs):
        """Mock requests.delete method"""
        return self._mock_requests_request('DELETE', url, **kwargs)
        
    def _mock_requests_patch(self, url, **kwargs):
        """Mock requests.patch method"""
        return self._mock_requests_request('PATCH', url, **kwargs)
        
    def _mock_ssl_context(self, *args, **kwargs):
        """Mock ssl.create_default_context"""
        class MockSSLContext:
            def __init__(self):
                pass
                
            def wrap_socket(self, sock, **kwargs):
                return sock
        
        return MockSSLContext()

    def __enter__(self):
        """Enable network interception"""
        self.patching_module = PatchingModule(self._patches)
        COMPOSITE_TRACER.push_module(self.patching_module)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Disable network interception"""
        if self.patching_module:
            COMPOSITE_TRACER.pop_config(self.patching_module)
            self.patching_module = None
        return False
    
    def analyze_data_exfiltration(self, tainted_data):
        """
        Analyze the captured network requests for potential data exfiltration.
        
        Args:
            tainted_data: Tainted data from Nidhogg's taint analysis
            
        Returns:
            List of potential data exfiltration attempts
        """
        exfiltration_attempts = []
        
        for request in self.intercepted_requests:
            # Look for tainted data in URL
            for data in tainted_data:
                data_str = str(data)
                if data_str in request.url:
                    exfiltration_attempts.append({
                        'type': 'URL',
                        'url': request.url,
                        'method': request.method,
                        'tainted_data': data_str,
                        'source_file': request.source_file,
                        'source_line': request.source_line
                    })
                
                # Look for tainted data in request body
                if request.data and data_str in str(request.data):
                    exfiltration_attempts.append({
                        'type': 'REQUEST_BODY',
                        'url': request.url,
                        'method': request.method,
                        'tainted_data': data_str,
                        'source_file': request.source_file,
                        'source_line': request.source_line
                    })
                    
                # Look for tainted data in headers
                for header_name, header_value in request.headers.items():
                    if data_str in str(header_value):
                        exfiltration_attempts.append({
                            'type': 'HEADER',
                            'url': request.url,
                            'method': request.method,
                            'header': header_name,
                            'tainted_data': data_str,
                            'source_file': request.source_file,
                            'source_line': request.source_line
                        })
        
        return exfiltration_attempts