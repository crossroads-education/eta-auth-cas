import * as querystring from "querystring";
import * as request from "request-promise";
import * as eta from "../../eta";
import * as db from "../../db";

@eta.mvc.route("/auth/cas")
@eta.mvc.controller()
export default class AuthCasController extends eta.IAuthController {
    @eta.mvc.raw()
    @eta.mvc.get()
    public async login(): Promise<void> {
        const loginUrl: string = eta.config.auth.cas.url + "login?"
            + querystring.stringify({
                cassvc: eta.config.auth.cas.svc,
                casurl: this.req.fullUrl
            });
        if (!this.req.query.casticket) {
            this.redirect(loginUrl);
            return;
        }
        const validateUrl: string = eta.config.auth.cas.url + "validate";
        const body: string = await request.get({
            url: validateUrl,
            qs: {
                cassvc: eta.config.auth.cas.svc,
                casticket: this.req.query.casticket,
                casurl: this.req.fullUrl
            }
        });
        if (body.startsWith("no")) {
            if (this.req.session.casAttempts > 0) {
                this.res.statusCode = eta.constants.http.AccessDenied;
                return;
            } else {
                this.req.session.casAttempts = 1;
                this.redirect(loginUrl);
            }
        } else if (body.startsWith("yes")) {
            this.req.session.casAttempts = 0;
            const username: string = body.split("\r\n")[1];
            const person: db.Person = await db.person().findOne({
                username
            });
            if (!person) {
                this.req.session["casUsername"] = username;
                await this.saveSession();
                return this.redirect("/auth/cas/register");
            }
            this.req.session.userid = person.id;
            await this.saveSession();
            this.redirect(this.req.session.authFrom);
        } else {
            throw new Error("Unknown response from CAS server: " + body);
        }
    }

    @eta.mvc.get()
    public async register(): Promise<void> { }

    @eta.mvc.raw()
    @eta.mvc.get()
    public async logout(): Promise<void> {
        this.req.session.userid = undefined;
        await this.saveSession();
        this.redirect(eta.config.auth.cas.url + "logout");
    }
}
