class CORSMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Get the origin from the request
        origin = request.headers.get('Origin')
        
        # List of allowed origins
        allowed_origins = [
            'https://development.stratosgaming.com',
            'https://api.stratosgaming.com',
            'http://localhost:5173',
            'http://localhost:5371',
            'http://63.177.102.145:5371',
            'http://63.177.102.145',
            'http://127.0.0.1:5173',
            'http://127.0.0.1:5371',
            'https://dev.d2lv8dn21inij8.amplifyapp.com',
            'https://stratosgaming.com',
            'https://www.stratosgaming.com',
        ]
        
        # Check if the origin is allowed
        if origin in allowed_origins:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
            response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken, X-Requested-With"
            response["Access-Control-Max-Age"] = "3600"
        
        return response

class CSPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Set CSP headers with updated connect-src to include development domain
        csp_policy = (
            "default-src 'self'; "
            "connect-src 'self' "
            "http://3.74.166.136:5371 "
            "http://localhost:5371 "
            "https://development.stratosgaming.com "
            "https://api.stratosgaming.com "
            "https://discord.com "
            "https://accounts.google.com; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "frame-ancestors 'self';"
        )
        
        response["Content-Security-Policy"] = csp_policy
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "SAMEORIGIN"
        response["X-XSS-Protection"] = "1; mode=block"
        
        return response 