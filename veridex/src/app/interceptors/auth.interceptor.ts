import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';

const backendBaseUrl = 'https://phishield-v01v.onrender.com';
const publicAuthPaths = ['/auth/login', '/auth/register'];

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();
  const isBackendRequest = req.url.startsWith(backendBaseUrl);
  const isPublicAuthRequest = publicAuthPaths.some((path) => req.url === `${backendBaseUrl}${path}`);

  if (!token || !isBackendRequest || isPublicAuthRequest) {
    return next(req);
  }

  return next(
    req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    })
  );
};
