# DISCLAIMER

## Product naming

This repository is **Filament-Test**: public test packaging of the Filament MMR light
client for the **Heaviest Chain Rule Test Network**. It is experimental testnet software,
not a production Filament release.

## Important Legal Notice

**PLEASE READ THIS DISCLAIMER CAREFULLY BEFORE USING THIS SOFTWARE**

### No Warranty

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Experimental Software

This library is **experimental** and under **active development**. It has NOT been:

- ❌ Formally audited for security vulnerabilities
- ❌ Tested in production environments at scale
- ❌ Certified for use in mission-critical systems
- ❌ Verified by independent third-party security researchers

### Security Considerations

#### Cryptographic Security

While this library implements cryptographic primitives (Weighted MMR / WeightedHash, Merkle-style proofs, PoW checks), **users are solely responsible for**:

1. **Key Management**: Securely generating, storing, and protecting private keys
2. **Network Security**: Ensuring secure communication channels with full nodes
3. **Peer Trust**: Validating the authenticity of full nodes providing proofs
4. **Genesis Validation**: Verifying genesis block hashes match official network values

#### Known Limitations

1. **Experimental product**: Filament-Test HTTP/P2P/wallet paths are under active testnet development and are not audited.
2. **Storage**: Default in-memory / file-oriented persistence is for testnet convenience (not a hardened wallet vault).
3. **Network / peers**: Outbound HTTPS and optional P2P expose your IP; prefer multiple Keystone endpoints (MNT) when available.
4. **Consensus trust**: Assumes at least one honest proof-serving full node among those you query; colluding peers can still mislead a light client.
5. **Protocol churn**: Wire formats and APIs can change between syncs from the private monorepo.


### Financial Risks

**THIS LIBRARY IS NOT DESIGNED FOR, AND SHOULD NOT BE USED IN, FINANCIAL APPLICATIONS WITHOUT EXTENSIVE ADDITIONAL SECURITY MEASURES.**

If you choose to use this library in a financial context (wallets, exchanges, payment systems):

- ⚠️ **You may lose funds** due to bugs, attacks, or implementation errors
- ⚠️ **You are solely responsible** for securing user assets
- ⚠️ **No support is guaranteed** for financial use cases
- ⚠️ **Conduct your own security audit** before production deployment
- ⚠️ **Test extensively** on testnets before handling real value

### Privacy Notice

This library:

- ✅ Does NOT collect or transmit user data
- ✅ Does NOT include telemetry or analytics
- ✅ Does NOT contact any servers except those explicitly configured

However, be aware that:

- ⚠️ Network requests reveal your IP address to full nodes
- ⚠️ Block/transaction queries may reveal your interests
- ⚠️ Storage backends may leave traces on disk
- ⚠️ Logs may contain sensitive information

**Users should implement their own privacy protections** (VPN, Tor, pruning) as needed.

### Regulatory Compliance

This library is a **general-purpose cryptographic tool** and is not designed for any specific regulatory framework.

**Users are solely responsible for**:

1. Ensuring compliance with local laws and regulations
2. Obtaining necessary licenses for financial services
3. Implementing KYC/AML requirements if applicable
4. Meeting data protection requirements (GDPR, CCPA, etc.)
5. Tax reporting and accounting obligations

The library authors make **no representations** regarding legal compliance and **assume no liability** for regulatory violations by users.

### Use at Your Own Risk

By using this software, you acknowledge that:

1. ✅ You have read and understood this disclaimer
2. ✅ You accept all risks associated with the software
3. ✅ You will not hold authors liable for any damages
4. ✅ You will conduct your own security review
5. ✅ You understand the experimental nature of the code

### Production Use Warning

**DO NOT USE IN PRODUCTION WITHOUT:**

1. ✅ Comprehensive security audit by qualified professionals
2. ✅ Extensive testing on testnets
3. ✅ Gradual rollout with monitoring
4. ✅ Incident response plan
5. ✅ Regular dependency updates and security patches
6. ✅ Backup and recovery procedures
7. ✅ Legal review for your jurisdiction

### Third-Party Dependencies

This library depends on third-party crates. The authors:

- ❌ Do NOT guarantee the security of dependencies
- ❌ Do NOT audit upstream code changes
- ❌ Are NOT responsible for vulnerabilities in dependencies

**Users should**:
- Regularly update dependencies
- Monitor security advisories
- Use `cargo audit` to detect known vulnerabilities

### Support and Maintenance

This is **open-source software** provided by volunteers.

**No guarantees are made regarding**:

- Response time to issues or pull requests
- Bug fixes or security patches
- Backward compatibility in future versions
- Long-term maintenance or support

**Commercial support is NOT available** at this time.

### Trademark Notice

"MMR Light Client" is not a registered trademark. Any logos, names, or branding are for identification purposes only and do not imply endorsement or affiliation with any organization.

### Export Restrictions

This software may contain cryptographic functionality. **Users are responsible for** complying with export control laws in their jurisdiction. The software may be restricted or prohibited in certain countries.

### Modifications and Forks

If you modify or fork this software:

1. ✅ You must retain this disclaimer
2. ✅ You must clearly indicate your modifications
3. ✅ You assume full responsibility for your changes
4. ✅ You should update version numbers to avoid confusion

### Dispute Resolution

Any disputes arising from the use of this software shall be resolved according to the laws of the jurisdiction where the user resides, WITHOUT recourse to the authors or contributors.

### Contact for Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Email security concerns to: [security@example.com]
3. Allow reasonable time for response (90 days)
4. Coordinate disclosure timing with maintainers

### Version and Updates

This disclaimer applies to:
- **Version**: 0.2.0
- **Last Updated**: February 2025

Disclaimer is subject to change without notice. Check the repository for the latest version.

---

## Summary

**TL;DR**: This is experimental software. Use at your own risk. Not audited. Not for production financial applications without extensive additional work. You are responsible for security, compliance, and any losses. No warranties. No guarantees. No support.

**By using this software, you agree to these terms.**

---

*If you do not agree with this disclaimer, DO NOT use this software.*
