// Depot portal front end: three views, hash routing, no framework.
const API = '/portal/api';

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, { credentials: 'same-origin', ...options });
  if (res.status === 401) {
    renderLogin(document.getElementById('main'));
    throw new Error('signed out');
  }
  if (!res.ok) throw new Error((await res.json()).error ?? res.statusText);
  return res.status === 204 ? null : res.json();
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'style') node.setAttribute('style', v);
    else node[k] = v;
  }
  node.append(...children);
  return node;
}

function renderLogin(main) {
  const error = el('p', { className: 'error' });
  const form = el('form', {},
    el('label', {}, 'Badge number ', el('input', { name: 'badge', autocomplete: 'username', required: true })),
    el('label', {}, 'PIN ', el('input', { name: 'pin', type: 'password', inputMode: 'numeric', maxLength: 6, required: true })),
    el('button', { type: 'submit' }, 'Sign in'),
    error);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    try {
      await api('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(data) });
      route();
    } catch (err) {
      error.textContent = err.message;
    }
  });
  main.replaceChildren(el('h1', {}, 'Sign in'), form);
}

async function renderDevices(main) {
  const search = el('input', { type: 'search', placeholder: 'Serial, model, bay…' });
  const tiles = el('div', { className: 'tiles' });
  const load = async () => {
    const devices = await api(`/devices?q=${encodeURIComponent(search.value)}`);
    tiles.replaceChildren(...devices.map((d) => el('div', { className: 'tile', style: `--hue: ${d.tile * 360 / 64}` },
      el('strong', {}, d.shortId), el('br'), d.model, el('br'), el('small', {}, `${d.depot} · bay ${d.bay ?? '–'} · ${d.serial}`))));
  };
  search.addEventListener('input', () => { load().catch(console.error); });
  main.replaceChildren(el('h1', {}, 'Devices'), search, tiles);
  await load();
}

async function renderPair(main) {
  const offer = await api('/pair', { method: 'POST' });
  const expires = new Date(offer.expires).toLocaleTimeString('en-GB');
  main.replaceChildren(
    el('h1', {}, 'Pair a device'),
    el('p', {}, `Scan this code with the device within five minutes (until ${expires}).`),
    el('pre', {}, JSON.stringify({ id: offer.id, depot: offer.depot, identity: offer.identity, key: offer.key }, null, 2)));
}

async function renderShipments(main) {
  main.replaceChildren(el('h1', {}, 'Shipments'), el('p', {}, 'Scan a cage label to change its status.'));
}

const routes = {
  '#/devices': renderDevices,
  '#/pair': renderPair,
  '#/shipments': renderShipments,
};

function route() {
  const view = routes[window.location.hash] ?? renderDevices;
  for (const a of document.querySelectorAll('nav a')) a.classList.toggle('active', a.getAttribute('href') === window.location.hash);
  view(document.getElementById('main')).catch((err) => console.error(err));
}

window.addEventListener('hashchange', route);
route();
