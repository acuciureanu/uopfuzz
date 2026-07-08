const express = require('express');
const ejs = require('ejs');
const app = express();

app.use(express.json());

// Set template engine
app.engine('ejs', ejs.renderFile);
app.set('views', __dirname);
app.set('view engine', 'ejs');

// Vulnerable endpoint - allows prototype pollution
// In the wild, this is common with recursive merge functions 
// or JSON.parse on object bodies etc without validation.
app.post('/pollute', (req, res) => {
    const payload = req.body;
    
    // Simulating deep merge weakness (lodash merge, deep-extend, etc)
    function merge(dst, src) {
        for (let key in src) {
            if (key === "__proto__") continue; // Naive protection, we bypass it via JSON parsing or other ways
            if (typeof src[key] === 'object' && src[key] !== null) {
                if (!dst[key]) dst[key] = {};
                merge(dst[key], src[key]);
            } else {
                dst[key] = src[key];
            }
        }
    }

    merge({}, payload);
    
    res.json({ status: "polluted", proto_cache: Object.prototype.cache ? 'yes' : 'no' });
});

// Render endpoint - triggers the EJS gadget
app.get('/render', (req, res) => {
    const template = '<h1>Hello <%= name %></h1>';
    const locals = { name: "World" };
    // Trigger compilation/rendering
    const result = ejs.render(template, locals);
    res.send(result);
});

// Clean the prototype 
app.get('/clean', (req, res) => {
    delete Object.prototype.outputFunctionName;
    delete Object.prototype.escapeFunction;
    delete Object.prototype.destructuredLocals;
    delete Object.prototype.cache;
    res.send("Cleaned");
});

const PORT = 3000;
app.listen(PORT, () => console.log(`EJS Test Server running on port ${PORT}`));
