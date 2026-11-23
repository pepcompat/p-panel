/**
 * P3 mock seed derived from the real lab scan in docs/evidence/2026-11-17/e2e-discovery-job.json
 * (9 nginx server blocks, upstream legacy_api, duplicate dup.example.lab on :80, 5 manual-review,
 * 1 php-fpm pool, 3 listeners). File contents are reconstructed fixtures that match the reported
 * server_name / listen / provenance lines; checksums are computed by the mock (not real sha256).
 */

/** Deterministic 64-hex digest (mock stand-in for sha256; never used for security). */
export function mockDigest(input: string): string {
  let out = '';
  let h1 = 0x811c9dc5;
  for (let round = 0; round < 8; round++) {
    let h = h1 ^ (round * 0x9e3779b1);
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    h1 = h;
    out += h.toString(16).padStart(8, '0');
  }
  return out;
}

export const LAB_FILES: Record<string, string> = {
  '/etc/nginx/nginx.conf': `user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
`,
  '/etc/nginx/conf.d/00-upstreams.conf': `# upstreams shared by legacy sites
upstream legacy_api {
    server lab-upstream-a:8080;
}
`,
  '/etc/nginx/conf.d/10-maps.conf': `# connection upgrade map
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
`,
  '/etc/nginx/sites-enabled/00-default-catchall.conf': `# catch-all: drop unknown hosts
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
`,
  '/etc/nginx/sites-enabled/01-static-multi.conf': `# static multi-domain site
server {
    listen 80;
    server_name example.lab www.example.lab static.example.lab;
    root /var/www/static;
    index index.html;
    include /etc/nginx/snippets/security-headers.conf;

    location / {
        try_files $uri $uri/ =404;
    }
}
`,
  '/etc/nginx/sites-enabled/02-php-legacy.conf': `# legacy PHP application
server {
    listen 80;
    server_name php.example.lab *.php.example.lab;
    root /var/www/php;
    index index.php index.html;
    include /etc/nginx/snippets/security-headers.conf;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location ~ /\\.ht {
        deny all;
    }
}
`,
  '/etc/nginx/sites-enabled/03-proxy-api.conf': `# API reverse proxy (rate limited)
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
server {
    listen 80;
    server_name api.example.lab;
    include /etc/nginx/snippets/proxy-common.conf;

    location / {
        limit_req zone=api burst=20;
        proxy_pass http://legacy_api;
    }

    location /health/ {
        proxy_pass http://legacy_api/health/;
    }
}
`,
  '/etc/nginx/sites-enabled/04-tls-secure.conf': `# TLS site
# certificate issued manually (lab CA)
server {
    listen 80;
    server_name secure.example.lab;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name secure.example.lab;
    ssl_certificate /etc/ssl/lab/secure.crt;
    ssl_certificate_key /etc/ssl/lab/secure.key;
    root /var/www/secure;
}
`,
  '/etc/nginx/sites-enabled/05-duplicate-a.conf': `# duplicate A
# NOTE: same server_name as 06-duplicate-b.conf
server {
    listen 80;
    server_name dup.example.lab;
    root /var/www/dup-a;
}
`,
  '/etc/nginx/sites-enabled/06-duplicate-b.conf': `# duplicate B
# NOTE: same server_name as 05-duplicate-a.conf
server {
    listen 80;
    server_name dup.example.lab;
    root /var/www/dup-b;
}
`,
  '/etc/nginx/sites-enabled/07-unusual-directives.conf': `# unusual directives (lab fixture)
# map/split_clients/geo live at http level and are not modelled by pPanel

map $host $tenant_root {
    default /var/www/unusual;
}

#
# A/B split
#

split_clients "\${remote_addr}" $variant {
    50% a;
    * b;
}

geo $is_office {
    default 0;
    10.0.0.0/8 1;
}

server {
    listen 80;
    server_name unusual.example.lab ~^legacy-(?<tenant>[a-z0-9]+)\\.example\\.lab$;
    root /var/www/unusual;

    if ($is_office = 0) {
        rewrite ^/admin /denied last;
    }

    location / {
        sub_filter 'http://' 'https://';
        sub_filter_once off;
    }
}
`,
  '/etc/nginx/snippets/security-headers.conf': `add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
`,
  '/etc/nginx/snippets/proxy-common.conf': `proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
`,
  '/etc/nginx/sites-enabled/shop.conf': `# shop storefront (hand-written, pre-pPanel)
server {
    listen 80;
    server_name shop.w3.co;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}
`,
};

/** Files whose content is not modelled (checksums taken verbatim from the lab report). */
export const LAB_EXTRA_FILES: Array<{ path: string; sha256: string }> = [
  {
    path: '/etc/nginx/mime.types',
    sha256: 'ba83e71ac786c4fac51ee7a2371053a12be3c5aa14e453763466bb7ed82abc8d',
  },
  {
    path: '/etc/nginx/snippets/fastcgi-php.conf',
    sha256: 'df5fcca537e8188df39eae4d2d39936e4cd0a218abfeacd70f2484ba73525b4e',
  },
  {
    path: '/etc/nginx/fastcgi.conf',
    sha256: '6b16418c0e9b44636f086148580f05e3d64ac9285ab890baea4b6ea8176f495e',
  },
];

export const LAB_SCAN_FILE_ORDER = [
  '/etc/nginx/nginx.conf',
  '/etc/nginx/mime.types',
  '/etc/nginx/conf.d/00-upstreams.conf',
  '/etc/nginx/conf.d/10-maps.conf',
  '/etc/nginx/sites-enabled/00-default-catchall.conf',
  '/etc/nginx/sites-enabled/01-static-multi.conf',
  '/etc/nginx/snippets/security-headers.conf',
  '/etc/nginx/sites-enabled/02-php-legacy.conf',
  '/etc/nginx/snippets/fastcgi-php.conf',
  '/etc/nginx/fastcgi.conf',
  '/etc/nginx/sites-enabled/03-proxy-api.conf',
  '/etc/nginx/snippets/proxy-common.conf',
  '/etc/nginx/sites-enabled/04-tls-secure.conf',
  '/etc/nginx/sites-enabled/05-duplicate-a.conf',
  '/etc/nginx/sites-enabled/06-duplicate-b.conf',
  '/etc/nginx/sites-enabled/07-unusual-directives.conf',
];

export interface LabServerBlock {
  key: string;
  names: string[];
  listen: string[];
  file: string;
  line: number;
  confidence: 'high' | 'medium' | 'low';
  manualReview: boolean;
  reasons: string[];
  unsupported: string[];
  root?: string;
  upstream?: string;
  fastcgiPass?: string;
  duplicateOf?: string;
}

const INC = '/etc/nginx/nginx.conf:30';
export const LAB_INCLUDED_FROM = INC;

/** The 9 server blocks reported by the lab scan (srv_* ids from the evidence file). */
export const LAB_SERVER_BLOCKS: LabServerBlock[] = [
  {
    key: 'srv_82d95dfe6f10',
    names: ['_'],
    listen: ['80 default_server'],
    file: '/etc/nginx/sites-enabled/00-default-catchall.conf',
    line: 2,
    confidence: 'medium',
    manualReview: false,
    reasons: ['no exact server_name', 'no root/proxy_pass/fastcgi_pass target'],
    unsupported: [],
  },
  {
    key: 'srv_bdeb57d131aa',
    names: ['example.lab', 'www.example.lab', 'static.example.lab'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/01-static-multi.conf',
    line: 2,
    confidence: 'high',
    manualReview: false,
    reasons: [],
    unsupported: [],
    root: '/var/www/static',
  },
  {
    key: 'srv_2d4e4947d9dd',
    names: ['php.example.lab', '*.php.example.lab'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/02-php-legacy.conf',
    line: 2,
    confidence: 'medium',
    manualReview: true,
    reasons: ['unsupported directives: set'],
    unsupported: ['set'],
    root: '/var/www/php',
    fastcgiPass: 'unix:/run/php/php8.3-fpm.sock',
  },
  {
    key: 'srv_cc77dcc3df48',
    names: ['api.example.lab'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/03-proxy-api.conf',
    line: 3,
    confidence: 'medium',
    manualReview: true,
    reasons: ['unsupported directives: limit_req'],
    unsupported: ['limit_req'],
    upstream: 'legacy_api',
  },
  {
    key: 'srv_3237daf70239',
    names: ['secure.example.lab'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/04-tls-secure.conf',
    line: 3,
    confidence: 'high',
    manualReview: false,
    reasons: ['no root/proxy_pass/fastcgi_pass target'],
    unsupported: [],
  },
  {
    key: 'srv_2735bc50ed3b',
    names: ['secure.example.lab'],
    listen: ['443 ssl http2'],
    file: '/etc/nginx/sites-enabled/04-tls-secure.conf',
    line: 9,
    confidence: 'high',
    manualReview: false,
    reasons: [],
    unsupported: [],
    root: '/var/www/secure',
  },
  {
    key: 'srv_a9b660fa968a',
    names: ['dup.example.lab'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/05-duplicate-a.conf',
    line: 3,
    confidence: 'medium',
    manualReview: true,
    reasons: ['duplicate server_name dup.example.lab on port 80'],
    unsupported: [],
    root: '/var/www/dup-a',
    duplicateOf: 'srv_31662e0c1de1',
  },
  {
    key: 'srv_31662e0c1de1',
    names: ['dup.example.lab'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/06-duplicate-b.conf',
    line: 3,
    confidence: 'medium',
    manualReview: true,
    reasons: ['duplicate server_name dup.example.lab on port 80'],
    unsupported: [],
    root: '/var/www/dup-b',
    duplicateOf: 'srv_a9b660fa968a',
  },
  {
    key: 'srv_1d8c05ed82f2',
    names: ['unusual.example.lab', '~^legacy-(?<tenant>[a-z0-9]+)\\.example\\.lab$'],
    listen: ['80'],
    file: '/etc/nginx/sites-enabled/07-unusual-directives.conf',
    line: 23,
    confidence: 'medium',
    manualReview: true,
    reasons: ['unsupported directives: if,rewrite,sub_filter,sub_filter_once'],
    unsupported: ['if', 'rewrite', 'sub_filter', 'sub_filter_once'],
    root: '/var/www/unusual',
  },
];

export const LAB_LISTENERS = [
  { address: '0.0.0.0', port: 80, process: 'nginx', pid: 7 },
  { address: '0.0.0.0', port: 443, process: 'nginx', pid: 7 },
  { address: '127.0.0.11', port: 43313, process: null, pid: null },
];

export const LAB_PHP_POOL = {
  name: 'www',
  file: '/etc/php/8.3/fpm/pool.d/www.conf',
  listen: '/run/php/php8.3-fpm.sock',
  phpVersion: '8.3',
  user: 'www-data',
};

export const LAB_UPSTREAM = {
  name: 'legacy_api',
  servers: ['lab-upstream-a:8080'],
  file: '/etc/nginx/conf.d/00-upstreams.conf',
  line: 2,
  includedFrom: '/etc/nginx/nginx.conf:29',
};

/** Mock `nginx -t`: balanced braces and every simple directive terminated by ';'. */
export function mockNginxTest(files: Array<{ path: string; content: string }>): {
  valid: boolean;
  output: string;
} {
  for (const f of files) {
    let depth = 0;
    const lines = f.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!.replace(/#.*$/, '').trim();
      if (!line) continue;
      const opens = (line.match(/\{/g) ?? []).length;
      const closes = (line.match(/\}/g) ?? []).length;
      depth += opens - closes;
      if (depth < 0)
        return {
          valid: false,
          output: `nginx: [emerg] unexpected "}" in ${f.path}:${i + 1}\nnginx: configuration file /etc/nginx/nginx.conf test failed`,
        };
      if (!line.endsWith('{') && !line.endsWith('}') && !line.endsWith(';')) {
        const directive = line.split(/\s+/)[0];
        return {
          valid: false,
          output: `nginx: [emerg] directive "${directive}" is not terminated by ";" in ${f.path}:${i + 1}\nnginx: configuration file /etc/nginx/nginx.conf test failed`,
        };
      }
    }
    if (depth !== 0)
      return {
        valid: false,
        output: `nginx: [emerg] unexpected end of file, expecting "}" in ${f.path}:${lines.length}\nnginx: configuration file /etc/nginx/nginx.conf test failed`,
      };
  }
  return {
    valid: true,
    output:
      'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful',
  };
}
