pem2jks.ts

# Usage

```ts
import Jks from 'pem2jks.ts';

// Jks password (Not pem key's)
const password = '12345678';

// Now, `jks` is the buffer of JavaKeyStore
const jks = await Jks.fromPEM(cert, key).getJKS(0x02, passsword);
```