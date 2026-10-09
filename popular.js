// Small hardcoded lists of popular package names, used only for typosquat hints.
export const POPULAR = {
  npm: ("react react-dom lodash express axios chalk commander debug typescript moment request async fs-extra tslib uuid yargs glob "
    + "minimist semver bluebird underscore inquirer webpack vue jquery rxjs core-js next eslint prettier jest mocha babel-core "
    + "dotenv body-parser cors mongoose mysql redis socket.io ws cheerio puppeteer node-fetch colors rimraf mkdirp through2 "
    + "classnames prop-types react-router redux react-redux styled-components tailwindcss postcss autoprefixer sass less "
    + "lodash-es date-fns dayjs zod joi ajv yaml js-yaml marked handlebars ejs pug express-session passport jsonwebtoken bcrypt "
    + "bcryptjs nodemailer winston pino morgan helmet compression cookie-parser multer sharp jimp ora execa got superagent "
    + "event-stream left-pad").split(" "),
  pypi: ("requests numpy pandas boto3 urllib3 setuptools six python-dateutil pyyaml certifi idna charset-normalizer typing-extensions "
    + "packaging pip wheel cryptography cffi pycparser attrs click jinja2 markupsafe werkzeug flask django fastapi pydantic "
    + "starlette uvicorn sqlalchemy psycopg2 psycopg2-binary pymysql redis celery scipy matplotlib scikit-learn tensorflow torch "
    + "keras pillow opencv-python beautifulsoup4 lxml selenium pytest pytest-cov mock tox black flake8 pylint mypy isort "
    + "colorama tqdm rich httpx aiohttp gunicorn protobuf grpcio google-api-core google-auth awscli botocore s3transfer "
    + "jmespath pyasn1 rsa docutils pygments simplejson ujson orjson toml tomli virtualenv filelock platformdirs zipp importlib-metadata "
    + "openai anthropic langchain transformers numba").split(" "),
};

export function lev(a, b, max = 2) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

export function typosquat(eco, name) {
  const n = name.toLowerCase();
  const list = POPULAR[eco];
  if (list.includes(n)) return { suspect: false };
  let best = null;
  for (const p of list) {
    const d = lev(n, p);
    if (d > 2) continue;
    if (p.length < 4 || n.length < 4) continue;
    if (d === 2 && p.length < 6) continue;
    if (!best || d < best.distance) best = { suspect: true, similarTo: p, distance: d };
  }
  return best || { suspect: false };
}
