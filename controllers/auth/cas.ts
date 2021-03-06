import * as eta from "../../eta";
import * as db from "../../db";

@eta.mvc.route("/auth/cas")
@eta.mvc.controller()
export default class ApiAuthCasController extends eta.IHttpController {
    @eta.mvc.get()
    public async register(): Promise<void> {
        if (eta.config.auth.provider !== "cre-auth-cas") {
            this.res.statusCode = eta.constants.http.AccessDenied;
        }
    }
}
