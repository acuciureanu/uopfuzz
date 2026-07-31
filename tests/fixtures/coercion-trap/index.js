// A benign function that coerces its argument to a primitive — exactly what
// date-fns set() does internally via new Date(...). It routes NOTHING to a code
// or command sink. Polluting Object.prototype.toString/valueOf with a function
// makes the JS ENGINE call it during this coercion, but that is engine behavior,
// not this library treating the property as attacker-controlled code. The
// reproduction gate must NOT report code execution here (the date-fns false
// positive this fixture pins).
module.exports = {
  set: function set(obj) {
    const d = new Date(obj);   // object -> primitive: calls valueOf/toString
    const s = `${obj}`;        // template coercion
    const n = Number(obj);     // numeric coercion
    return { d: String(d), s, n };
  },
};
