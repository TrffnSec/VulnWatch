// These functions are serialized by chrome.scripting: keep them self-contained.
export function capturePage() {
  const clean = value => typeof value === 'string' ? value.slice(0, 2048) : '';
  return {
    href: location.origin + location.pathname,
    generators: Array.from(document.querySelectorAll('meta[name="generator" i]')).slice(0, 15).map(e => clean(e.content)),
    resources: Array.from(document.querySelectorAll('script[src],link[rel="stylesheet"][href]')).slice(0, 400).map(e => clean(e.src || e.href)),
    markers: {
      next: Boolean(document.getElementById('__NEXT_DATA__') || document.querySelector('script[src*="/_next/static/"]')),
      nuxt: Boolean(document.getElementById('__nuxt') || document.querySelector('script[src*="/_nuxt/"]')),
      angular: clean(document.querySelector('[ng-version]')?.getAttribute('ng-version')),
      webflow: document.documentElement.hasAttribute('data-wf-site'),
      drupal: Boolean(document.querySelector('[data-drupal-selector]'))
    },
    limits: {resources: document.querySelectorAll('script[src],link[rel="stylesheet"][href]').length > 400}
  };
}

export function captureRuntime() {
  // Avoid deliberately invoking page-defined getters. Runtime values remain untrusted claims.
  function own(obj, key) {
    if (!obj || !['object', 'function'].includes(typeof obj)) return undefined;
    try { const d = Object.getOwnPropertyDescriptor(obj, key); return d && 'value' in d ? d.value : undefined; } catch { return undefined; }
  }
  function path(parts) { let v = window; for (const p of parts) v = own(v, p); return v; }
  const definitions = [
    ['jquery', ['jQuery', 'fn', 'jquery']], ['vue', ['Vue', 'version']],
    ['react', ['React', 'version']], ['react-dom', ['ReactDOM', 'version']],
    ['angular', ['angular', 'version', 'full']], ['lodash', ['_', 'VERSION']],
    ['moment', ['moment', 'version']], ['d3', ['d3', 'version']],
    ['axios', ['axios', 'VERSION']], ['handlebars', ['Handlebars', 'VERSION']],
    ['dompurify', ['DOMPurify', 'version']], ['chart.js', ['Chart', 'version']],
    ['highlight.js', ['hljs', 'versionString']], ['backbone', ['Backbone', 'VERSION']],
    ['bootstrap', ['bootstrap', 'Tooltip', 'VERSION']]
  ];
  const found = [];
  for (const [id, parts] of definitions) {
    const v = path(parts);
    if (typeof v !== 'string' || v.length > 60) continue;
    // Both lodash and underscore use _.VERSION. Require a lodash-specific method.
    if (id === 'lodash' && typeof path(['_', 'cloneDeep']) !== 'function') {
      if (typeof path(['_', 'template']) === 'function') found.push({id:'underscore', version:v, signal:'_.VERSION'});
      continue;
    }
    found.push({id, version:v, signal:parts.join('.')});
  }
  const jqBootstrap = path(['jQuery', 'fn', 'tooltip', 'Constructor', 'VERSION']);
  if (typeof jqBootstrap === 'string' && jqBootstrap.length < 60) found.push({id:'bootstrap', version:jqBootstrap, signal:'jQuery.fn.tooltip.Constructor.VERSION'});
  return found;
}
