import sys
import re
import yaml
from responses import RequestsMock

INTERPOLATIONS = [
    ("%CLIENT_MAJOR_VERSION%", "r0")
]

def interpolate_str(s):
    for interpolation in INTERPOLATIONS:
        s = s.replace(interpolation[0], interpolation[1])
    return s

def endpoint_to_regex(s):
    # TODO sub by with more specific REGEXes per type
    # e.g. roomId, eventId, userId
    return re.sub('\{[a-zA-Z]+\}', '[a-zA-Z!\.:-@#]+', s)

MISSING_BASE_PATH = "Not a valid API Base Path: "
MISSING_ENDPOINT = "Not a valid API Endpoint: "
MISSING_METHOD = "Not a valid API Method: "

class ApiGuide:
    def __init__(self, hostname="http://example.com"):
        self.hostname = hostname
        self.endpoints = {}
        self.called = []
        self.missing = []
        self.total_endpoints = 0

    def setup_from_files(self, files):
        for file in files:
            with open(file) as rfile:
                definitions = yaml.load(rfile)
                base_path = definitions['basePath']
                resolved_base_path = interpolate_str(base_path)
                if resolved_base_path not in self.endpoints:
                    self.endpoints[resolved_base_path] = {}
                regex_paths = { endpoint_to_regex(k): v for k,v in definitions['paths'].items() }
                self.endpoints[resolved_base_path].update(regex_paths)
                endpoints_added = sum(len(v) for v in definitions['paths'].values())
                self.total_endpoints += endpoints_added

    def process_request(self, request):
        full_path_url = request.url
        method = request.method
        body = request.body
        for base_path in self.endpoints.keys():
            if base_path in full_path_url:
                path_url = full_path_url.replace(base_path, '')
                path_url = path_url.replace(self.hostname, '')
                break
        else:
            self.add_called_missing(MISSING_BASE_PATH, request)
            return
        endpoints = self.endpoints[base_path]
        for endpoint in endpoints.keys():
            if re.fullmatch(endpoint, path_url):
                break
        else:
            self.add_called_missing(MISSING_ENDPOINT, request)
            return
        endpoint_def = endpoints[endpoint]
        try:
            endpoint_def[method.lower()]
            self.add_called(base_path, endpoint, method, body)
        except KeyError:
            self.add_called_missing(MISSING_METHOD, request)


    def add_called(self, base_path, endpoint, method, body):
        self.called.append((base_path, endpoint, method, body))

    def add_called_missing(self, error,request):
        self.missing.append((error, request.url, request.method, request.body))

    def summary(self):
        print("Accessed: %i endpoints out of %i -- %0.2f%% Coverage." %
            (len(self.called), self.total_endpoints, len(self.called)*100 / self.total_endpoints)
        )
        if self.missing:
            missing_summary = "\n".join(m[0] + ", ".join(m[1:-1]) for m in self.missing)
            raise AssertionError("The following invalid API Requests were made:\n" +
                missing_summary)

class RequestsMockWithApiGuide(RequestsMock):
    def __init__(self, api_guide, assert_all_requests_are_fired=True):
        self.api_guide = api_guide
        super().__init__(assert_all_requests_are_fired)

    def _on_request(self, adapter, request, **kwargs):
        self.api_guide.process_request(request)
        return super()._on_request(adapter, request, **kwargs)
