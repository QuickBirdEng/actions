import { createHash, createHmac } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join, resolve, sep } from 'node:path'

const EMPTY_PAYLOAD_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

function required(name) {
  const value = process.env[name]
  if (!value) {
    console.error(`::error::${name} is not set`)
    process.exit(1)
  }
  return value
}

const accessKey = required('SPACES_ACCESS_KEY')
const secretKey = required('SPACES_SECRET_KEY')
const spaceName = required('SPACES_NAME')
const region = required('SPACES_REGION')
const keyPrefix = required('SPACES_KEY_PREFIX')
const destination = resolve(required('DESTINATION'))

const host = `${spaceName}.${region}.digitaloceanspaces.com`

const encodeRfc3986 = (value) =>
  encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`)

const encodePath = (key) => `/${key.split('/').map(encodeRfc3986).join('/')}`

const sha256 = (value) => createHash('sha256').update(value).digest('hex')
const hmac = (key, value) => createHmac('sha256', key).update(value).digest()

const decodeXml = (value) =>
  value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')

function signedRequest(canonicalUri, query) {
  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')
  const dateStamp = amzDate.slice(0, 8)
  const scope = `${dateStamp}/${region}/s3/aws4_request`

  const canonicalQuery = Object.keys(query)
    .sort()
    .map((key) => `${encodeRfc3986(key)}=${encodeRfc3986(query[key])}`)
    .join('&')

  const signedHeaders = { host, 'x-amz-content-sha256': EMPTY_PAYLOAD_SHA256, 'x-amz-date': amzDate }
  const headerNames = Object.keys(signedHeaders).sort()
  const canonicalHeaders = headerNames.map((name) => `${name}:${signedHeaders[name]}\n`).join('')

  const canonicalRequest = [
    'GET',
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    headerNames.join(';'),
    EMPTY_PAYLOAD_SHA256,
  ].join('\n')

  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n')

  let signingKey = hmac(`AWS4${secretKey}`, dateStamp)
  for (const part of [region, 's3', 'aws4_request']) signingKey = hmac(signingKey, part)
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex')

  return {
    url: `https://${host}${canonicalUri}${canonicalQuery ? `?${canonicalQuery}` : ''}`,
    // `host` is set by the HTTP client itself and must not be passed explicitly.
    headers: {
      'x-amz-content-sha256': EMPTY_PAYLOAD_SHA256,
      'x-amz-date': amzDate,
      authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${headerNames.join(';')}, Signature=${signature}`,
    },
  }
}

async function get(canonicalUri, query = {}) {
  const { url, headers } = signedRequest(canonicalUri, query)
  const response = await fetch(url, { headers })
  if (!response.ok) {
    const body = await response.text().catch(() => '')
    throw new Error(`GET ${canonicalUri} failed with ${response.status} ${response.statusText}\n${body}`)
  }
  return response
}

async function listKeys() {
  const keys = []
  let continuationToken

  do {
    const query = { 'list-type': '2', prefix: keyPrefix, 'max-keys': '1000' }
    if (continuationToken) query['continuation-token'] = continuationToken

    const xml = await (await get('/', query)).text()
    for (const match of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) keys.push(decodeXml(match[1]))

    const truncated = /<IsTruncated>\s*true\s*<\/IsTruncated>/.test(xml)
    continuationToken = truncated ? xml.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/)?.[1] : undefined
  } while (continuationToken)

  return keys
}

const keys = await listKeys()

if (keys.length === 0) {
  console.log(`No objects found under '${keyPrefix}' in ${spaceName}`)
  process.exit(0)
}

for (const key of keys) {
  const relativePath = key.slice(keyPrefix.length).replace(/^\/+/, '')
  const target = resolve(join(destination, relativePath))
  if (target !== destination && !target.startsWith(destination + sep)) {
    throw new Error(`Refusing to write '${key}' outside of '${destination}'`)
  }

  const response = await get(encodePath(key))
  await mkdir(dirname(target), { recursive: true })
  await writeFile(target, Buffer.from(await response.arrayBuffer()))
  console.log(`Downloaded ${key} -> ${target}`)
}

console.log(`Downloaded ${keys.length} object(s) from '${keyPrefix}'`)
