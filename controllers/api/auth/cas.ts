import * as eta from "../../../eta";
import * as db from "../../../db";

@eta.mvc.route("/api/auth/cas")
@eta.mvc.controller()
export default class ApiAuthCasController extends eta.IHttpController {
    @eta.mvc.raw()
    @eta.mvc.post()
    public async register(partial: Partial<db.Person>): Promise<void> {
        if (!this.req.session["casUsername"]) {
            this.res.statusCode = eta.constants.http.AccessDenied;
            return;
        }
        let person: db.Person = await db.person().findOne({ username: this.req.session["casUsername"] });
        if (person) {
            return this.redirect("/login");
        }
        person = new db.Person(eta._.extend({
            username: this.req.session["casUsername"]
        }, partial));
        await db.person().save(person);
        this.redirect("/login");
    }
}
