// Improved axios configuration for cross-origin CSRF cookies
// This is a suggested improvement for your frontend axios.ts file

import axios from 'axios';
import { getBackendUrl } from '../utils/Utility';

// Configure axios defaults
axios.defaults.baseURL = getBackendUrl();
axios.defaults.withCredentials = true;

// Enhanced CSRF token getter function
function getCSRFToken(): string | null {
  // Try to get CSRF token from multiple sources
  const cookies = document.cookie.split(';').map(cookie => cookie.trim());
  const csrfCookie = cookies.find(cookie => cookie.startsWith('csrftoken='));
  
  if (csrfCookie) {
    return csrfCookie.split('=')[1];
  }
  
  // Fallback: try to get from meta tag if available
  const metaTag = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement;
  if (metaTag) {
    return metaTag.content;
  }
  
  return null;
}

// Add request interceptor to always include CSRF token
axios.interceptors.request.use(
  (config) => {
    // Include CSRF token for all state-changing requests
    const csrfToken = getCSRFToken();
    if (csrfToken && ['post', 'put', 'patch', 'delete'].includes(config.method?.toLowerCase() || '')) {
      config.headers['X-CSRFToken'] = csrfToken;
    }
    
    // Ensure proper headers for cross-origin requests
    config.headers['Content-Type'] = config.headers['Content-Type'] || 'application/json';
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor to handle CSRF errors
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 403 && 
        error.response?.data?.includes?.('CSRF') || 
        error.response?.statusText === 'Forbidden') {
      
      console.warn('CSRF error detected, attempting to refresh CSRF token...');
      
      // Try to refresh CSRF token
      try {
        await ensureCSRFCookie();
        
        // Retry the original request
        const originalRequest = error.config;
        const newToken = getCSRFToken();
        
        if (newToken) {
          originalRequest.headers['X-CSRFToken'] = newToken;
          return axios(originalRequest);
        }
      } catch (refreshError) {
        console.error('Failed to refresh CSRF token:', refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

// Enhanced function to ensure CSRF cookie is set
export async function ensureCSRFCookie(): Promise<void> {
  try {
    console.log('Fetching CSRF cookie from:', `${getBackendUrl()}/auth/csrf_cookie`);
    
    const response = await fetch(`${getBackendUrl()}/auth/csrf_cookie`, {
      method: 'GET',
      credentials: 'include', // Essential for cross-origin cookies
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
    });
    
    // Log response details for debugging
    console.log('CSRF Cookie Response:', {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch CSRF cookie: ${response.status} ${response.statusText}`);
    }

    // Wait a moment for the cookie to be set
    await new Promise(resolve => setTimeout(resolve, 100));

    // Check if the cookie was set
    const cookies = document.cookie.split(';').map(cookie => cookie.trim());
    console.log('All cookies after CSRF request:', cookies);
    
    // Specifically check for csrftoken
    const csrfCookie = cookies.find(cookie => cookie.startsWith('csrftoken='));
    console.log('CSRF Cookie found:', csrfCookie ? 'Yes' : 'No');
    
    if (!csrfCookie) {
      console.error('CSRF cookie not found after request. This might be a cross-origin cookie issue.');
      console.log('Troubleshooting tips:');
      console.log('1. Check that the backend sets SameSite=None and Secure=true');
      console.log('2. Verify CORS settings allow credentials');
      console.log('3. Ensure both frontend and backend use HTTPS');
    }
    
  } catch (error) {
    console.error('Failed to get CSRF cookie:', error);
    throw error;
  }
}

// Function to manually refresh CSRF token
export async function refreshCSRFToken(): Promise<string | null> {
  await ensureCSRFCookie();
  return getCSRFToken();
}

// Initialize CSRF cookie on app load
ensureCSRFCookie().catch(error => {
  console.error('Failed to initialize CSRF cookie:', error);
});

export default axios;
export { getCSRFToken }; 