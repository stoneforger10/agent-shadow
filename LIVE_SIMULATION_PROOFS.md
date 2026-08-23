# Live StudioNet simulation proofs

## Reversible action

- Create: https://explorer-studio.genlayer.com/tx/0x3652d24e555fc687f6b5b5e65cb253a3229cb1bce10bae035a62f970375fab91
- Simulate: https://explorer-studio.genlayer.com/tx/0xa3305ff42cc0335acaa0eb87db700febb63b736f60bc50c36271da9745cebd64
- Decision: `ALLOW`
- Action state: `ALLOWED`
- Execution gate: `true`
- Scenario fingerprint: `48267a5a8dd04f89d291adc214dcd1c40f5890bbc8bcb14e7716e064060074bd`

## Irreversible action

- Create: https://explorer-studio.genlayer.com/tx/0x43190350f57f03df7d7f6dd8065fb56c040804f1bd30be30d230c0f7b65607b4
- Simulate: https://explorer-studio.genlayer.com/tx/0x6c28fc074f4153def0b030a7fe486ae9223c70ba23d4c2005003e85dfb6e2ef2
- Independent approval: https://explorer-studio.genlayer.com/tx/0xc48a19bb604e0412fdbc15bd379d9f20422d93aaefe655a0fc35b46904735df2
- Decision: `HUMAN_REVIEW`
- Action state after distinct reviewer approval: `REVIEW_APPROVED`
- Execution gate: `true`
- Scenario fingerprint: `ef5882b434ad1f1b9d7f0f6889bfed1bfc1c99a5ae1c61f99ecfec28ab65fb75`

All transactions finalized with `MAJORITY_AGREE`. Both evidence sources returned
HTTP 200. Validators independently reproduced exact three-scenario vectors,
divergence, reversibility and fingerprints.
