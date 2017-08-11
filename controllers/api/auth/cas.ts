import * as eta from "../../../eta";
import * as db from "../../../db";

@eta.mvc.route("/api/auth/cas")
@eta.mvc.controller()
export default class ApiAuthCasController extends eta.IHttpController {
    @eta.mvc.raw()
    @eta.mvc.post()
    @eta.mvc.params(["firstName", "lastName", "email"])
    public async register(firstName: string, lastName: string, email: string): Promise<void> {
        if (!this.req.session["casUsername"]) {
            this.res.statusCode = eta.constants.http.AccessDenied;
            return;
        }
        let person: db.Person = await db.person().findOne({ username: this.req.session["casUsername"] });
        if (person) {
            return this.redirect("/login");
        }
        person = new db.Person({
            firstName,
            lastName,
            username: this.req.session["casUsername"],
            email
        });
        await db.person().save(person);
        this.redirect("/login");
    }
}
