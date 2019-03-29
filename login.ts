/* External dependencies */
import { Injectable } from '@angular/core';
import { InAppBrowser, InAppBrowserEvent } from '@ionic-native/in-app-browser/ngx';
import { HttpClient, HttpHeaders, HttpParams, HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { Observer } from 'rxjs/Observer';
import { ReplaySubject } from 'rxjs/ReplaySubject';

/* Imports from this module (in same directory) */
import {
  ILoginProvider,
  ICredentialsLoginResponse,
  ISession,
  ICredentials,
  IOIDCLoginResponse,
  IAction,
  ELoginErrors,
  ILoginRequest,
  ILoginConfig_SSO,
  ILoginConfig_OIDC,
  ILoginConfig_Credentials,
  IOIDCRefreshResponseObject, IOIDCUserInformationResponse
} from './interfaces';
import {
  WebHttpUrlEncodingCodec,
  isSubset,
  constructPluginUrl
} from './lib';

// set to true to see output
const debugMode = true;

/**
 * Prints text only if global debug variable has been set
 * @param text
 */
export function debug(text) {
  if (debugMode) {
    console.log(`[LoginProvider]:${text}`);
  }
}


/**
 * LoginProvider
 *
 * only the login(credentials, authConfig) method can be called from the outside.
 * The 'authConfig' parameter should contain a member named 'method' having one
 * of the following values
 *
 *  - "sso" (for executing Single Sign On)
 *  - "oidc" (for executing OpenID connect)
 *  - "credentials" (for executing normal username/password login)
 *
 * the LoginProvider will execute the right method internally and return the
 * created session (or an error).
 */
@Injectable()
export class UPLoginProvider implements ILoginProvider {

  // events that can occur in InAppBrowser during SSO login
  private ssoBrowserEvents = {
    loadStart:  'loadstart',
    loadStop:   'loadstop',
    loadError:  'loaderror',
    exit:       'exit'
  };

  // predefined actions that will be used
  private ssoActions: IAction[] = [
    {
      // obtains token from URL
      event: this.ssoBrowserEvents.loadStart,
      condition: (event, loginRequest) => {
        return isSubset(event.url, loginRequest.ssoConfig.ssoUrls.tokenUrl) ||
          isSubset(event.url, ('http://' + loginRequest.ssoConfig.ssoUrls.tokenUrl));
      },
      action: (event, loginRequest, observer) => {
        if (isSubset(event.url, loginRequest.ssoConfig.ssoUrls.tokenUrl) ||
          isSubset(event.url, ('http://' + loginRequest.ssoConfig.ssoUrls.tokenUrl))) {

          let token = event.url;
          token = token.replace('http://', '');
          token = token.replace(loginRequest.ssoConfig.ssoUrls.tokenUrl, '');
          debug(`[ssoLogin] token ${token}`);
          try {
            token = atob(token);

            // Skip the passport validation, just trust the token
            token = token.split(':::')[1];
            debug(`[ssoLogin] Moodle token found: ${token}`);

            const session: ISession = {
              credentials:  loginRequest.credentials,
              token:        token,
              timestamp:    new Date()
            };

            debug('[ssoLogin] Session created');

            observer.next(session);
            observer.complete();
          } catch (error) {
            // TODO: check what caused the error
            observer.error({reason: ELoginErrors.TECHNICAL, error: error});
          }
        }
      }
    },
    {
      // checks whether a login form is present and then injects code for login
      event: this.ssoBrowserEvents.loadStop,
      condition: (event, loginRequest) => {
        return isSubset(event.url, loginRequest.ssoConfig.ssoUrls.idpBaseUrl) &&
          !loginRequest.loginAttemptStarted;
      },
      action: async (event, loginRequest, subject) => {
        debug('[ssoLogin] Testing for login form');

        // Test for a login form
        const testForLoginForm = '$("form#login").length;';
        const length = await loginRequest.ssoConfig.browser.executeScript({ code: testForLoginForm });

        if (length[0] >= 1) {
          debug('[ssoLogin] Login form present');

          // Create code for executing login in browser
          const enterCredentials =
            `$("form#login #username").val(\'${loginRequest.credentials.username}\');
             $("form#login #password").val(\'${loginRequest.credentials.password}\');
             $("form#login .loginbutton").click();`;

          loginRequest.loginAttemptStarted = true;

          debug('[ssoLogin] Injecting login code now');
          loginRequest.ssoConfig.browser.executeScript({code: enterCredentials});
        }
      }
    },
    {
      //
      event: this.ssoBrowserEvents.loadError,
      condition: (event, loginRequest) => true,
      action: (event, loginRequest, observer) => {
        // TODO: something should be done here, I guess
      }
    },
    {
      // happens when user closes browser
      event: this.ssoBrowserEvents.exit,
      condition: () => true,
      action: (event, loginRequest, observer) => {
        observer.error({
          reason: ELoginErrors.TECHNICAL,
          description: 'User closed browser'
        });
      }
    }
  ];

  constructor(
      public http: HttpClient,
      public inAppBrowser: InAppBrowser) {
  }

  /**
   * Handles ssoBrowserEvents by executing defined actions if event type matches
   * and condition function of action returns true
   *
   * @param {InAppBrowserEvent} event
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  private handleSsoEvent(event: InAppBrowserEvent,
                         loginRequest: ILoginRequest,
                         observer: Observer<ISession>) {

    // test all defined ssoActions
    for (const ssoAction of this.ssoActions) {
      // execute action if event type matches and condition functions returns true
      if (ssoAction.event === event.type && ssoAction.condition(event, loginRequest)) {
        ssoAction.action(event, loginRequest, observer);
      }
    }
  }

  /**
   * Performs a SSO login by creating an InAppBrowser object and attaching
   * listeners to it. When SSO login has been performed the given observer is
   * used to return the created ISession (happens in ssoAction)
   *
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  public ssoLogin(credentials: ICredentials, loginConfig: ILoginConfig_SSO): Observable<ISession> {
    debug('[ssoLogin] Doing ssoLogin');

    const loginRequest: ILoginRequest = {
      credentials: credentials,
      ssoConfig: loginConfig,
      loginAttemptStarted: false
    };

    if (!loginRequest.ssoConfig.browser) {
      debug('[ssoLogin] Browser is undefined, will create one');
      // If no browser is given create browser object by loading URL
      loginRequest.ssoConfig.browser = this.inAppBrowser.create(
        constructPluginUrl(
          loginRequest.ssoConfig.ssoUrls.pluginUrl,
          loginRequest.ssoConfig.ssoUrls.pluginUrlParams
        ),
        '_blank',
        {clearcache: 'yes', clearsessioncache: 'yes'}
      );
    }

    const rs = new ReplaySubject<any>();

    new Observable(
      observer => {
        for (const event in this.ssoBrowserEvents) {
          if (event) {
            loginRequest.ssoConfig.browser.on(this.ssoBrowserEvents[event]).subscribe(
              (eventRes: InAppBrowserEvent) => {
                this.handleSsoEvent(eventRes, loginRequest, observer);
              }
            );
          }
        }
      }
    ).subscribe(
      session => {
        debug('[ssoLogin] Success, closing browser now');
        loginRequest.ssoConfig.browser.close();
        setTimeout(
          () => {
            rs.next(session);
          }, 2000
        );
      },
      error => {
        debug('[ssoLogin] Failed, closing browser now');
        loginRequest.ssoConfig.browser.close();
        setTimeout(
          () => {
            rs.error(error);
          }, 2000
        );
      }
    );

    return rs;
  }

  /**
   * Performs login with provided loginRequest. Returns created session or error
   * with provided observer object.
   *
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  public credentialsLogin(credentials: ICredentials, loginConfig: ILoginConfig_Credentials): Observable<ISession> {
    debug('[credentialsLogin] Doing credentialsLogin');

    const url: string = loginConfig.moodleLoginEndpoint;

    const headers: HttpHeaders = new HttpHeaders()
      .append('Authorization',       loginConfig.accessToken);

    const params: HttpParams = new HttpParams({encoder: new WebHttpUrlEncodingCodec()})
      .append('username',           credentials.username)
      .append('password',           credentials.password)
      .append('service',            loginConfig.service)
      .append('moodlewsrestformat', loginConfig.moodlewsrestformat);

    const rs = new ReplaySubject<ISession>();

    this.http.get(url, {headers: headers, params: params}).subscribe(
      (response: ICredentialsLoginResponse) => {
        if (response.token) {
          rs.next({
            credentials:  credentials,
            token:        response.token,
            timestamp:    new Date()
          });
          rs.complete();
        } else {
          rs.error({reason: ELoginErrors.AUTHENTICATION});
        }
      },
      (error: HttpErrorResponse) => {
        // some other error
        rs.error({reason: ELoginErrors.UNKNOWN_ERROR, error: error});
      }
    );

    return rs;
  }

  /**
   * executes OIDC login
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  public oidcLogin(credentials: ICredentials, loginConfig: ILoginConfig_OIDC): Observable<ISession> {
    debug('[oidcLogin] Doing oidcLogin');

    const tokenUrl: string = loginConfig.tokenUrl;

    const headers: HttpHeaders = new HttpHeaders()
      .append('Authorization',    loginConfig.accessToken)
      .append('Content-Type',     loginConfig.contentType);

    const params: HttpParams = new HttpParams({encoder: new WebHttpUrlEncodingCodec()})
      .append('grant_type',       loginConfig.grantType_password)
      .append('username',         credentials.username)
      .append('password',         credentials.password)
      .append('scope',            loginConfig.scope);


    const rs = new ReplaySubject<ISession>();

    this.http.post(tokenUrl, params, {headers: headers}).subscribe(
      (response: IOIDCLoginResponse) => {
        // create session object with access_token as token, but also attach
        // the whole response in case it's needed
        rs.next({
          credentials:      credentials,
          token:            response.access_token,
          oidcTokenObject:  response,
          timestamp:        new Date()
        });
        rs.complete();
      },
      (error) => {
        // Authentication error
        // TODO: Add typing for errors?
        if (error.status = 401) {
          rs.error({reason: ELoginErrors.AUTHENTICATION});
        }
      }
    );

    return rs;
  }

  /**
   * refreshes OIDC token with refreshToken and the loginConfig. Returns an object
   * containing new OIDC-Response-Object and a timestamp.
   * @param refreshToken
   * @param loginConfig
   */
  public oidcRefreshToken(refreshToken: string,
                          loginConfig: ILoginConfig_OIDC): Observable<IOIDCRefreshResponseObject> {
    debug('[oidcLogin] Doing oidc token refresh');

    const tokenUrl: string = loginConfig.tokenUrl;

    const headers: HttpHeaders = new HttpHeaders()
      .append('Authorization',    loginConfig.accessToken)
      .append('Content-Type',     loginConfig.contentType);

    const params: HttpParams = new HttpParams({encoder: new WebHttpUrlEncodingCodec()})
      .append('grant_type',       loginConfig.grantType_refresh)
      .append('refresh_token',    refreshToken);

    const rs = new ReplaySubject<IOIDCRefreshResponseObject>();

    this.http.post(tokenUrl, params, {headers: headers}).subscribe(
      (response: IOIDCLoginResponse) => {
        // create session object with access_token as token, but also attach
        // the whole response in case it's needed
        rs.next({
          oidcTokenObject:  response,
          timestamp:        new Date()
        });
        rs.complete();
      },
      (response) => {
        console.log(response);
        // Authentication error
        if (response.status = 401) {
          let errorDescription, error;
          if (response.error && response.error.error_description && response.error.error) {
            errorDescription = response.error.error_description;
            error = response.error.error;
          }

          rs.error({ reason: ELoginErrors.AUTHENTICATION, error: error, description: errorDescription });
        }
      }
    );

    return rs;
  }

  /**
   * returns information about user via OIDC
   * @param userToken
   * @param loginConfig
   */
  public oidcGetUserInformation(session: ISession,
                                loginConfig: ILoginConfig_OIDC): Observable<IOIDCUserInformationResponse> {
    debug('[oidcLogin] Retrieving OIDC user information');

    const userInfoUrl: string = loginConfig.userInformationUrl;

    const headers: HttpHeaders = new HttpHeaders()
      .append('Authorization',    `${session.oidcTokenObject.token_type} ${session.oidcTokenObject.access_token}`);

    const rs = new ReplaySubject<IOIDCUserInformationResponse>();

    this.http.get(userInfoUrl, {headers: headers, params: {schema: loginConfig.userInfoParams.schema}}).subscribe(
      (response: IOIDCUserInformationResponse) => {
        rs.next(response);
        rs.complete();
      },
      error => {
        console.log(error);
        // Authentication error
        if (error.status = 401) {
          rs.error({reason: ELoginErrors.AUTHENTICATION});
        }
      }
    );

    return rs;
  }

  /**
   * Allows adding custom sso actions from outside
   * @param {IAction} ssoAction
   */
  public addSSOaction(ssoAction: IAction) {
    this.ssoActions.push(ssoAction);
  }


}
