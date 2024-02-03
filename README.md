pem2jks.ts

# Usage

```ts
import Jks from 'pem2jks.ts';

// Now, `jks` is the buffer of JavaKeyStore
const jks = await Jks.fromPEM(cert, key, passsword).getJKS(0x02);
```