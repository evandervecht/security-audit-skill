import { Injectable } from '@angular/core';
import { HttpEvent, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';

const TRUSTED_ORIGINS = [
  'https://api.myapp.com',
  'https://auth.myapp.com'
];

@Injectable()
export class AuthTokenService {
  addToken(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const isTrusted = TRUSTED_ORIGINS.some(origin => req.url.startsWith(origin));

    if (isTrusted) {
      const token = localStorage.getItem('auth_token');
      if (token) {
        const authReq = req.clone({
          setHeaders: { Authorization: `Bearer ${token}` }
        });
        return next.handle(authReq);
      }
    }

    return next.handle(req);
  }
}
