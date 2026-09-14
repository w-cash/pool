# Future work

- [ ] Add an account-visible payout destination change history. Record the
  asset, masked old and new destination, threshold and automatic-payout
  policy, request time, safety-hold release time, activation or cancellation,
  and the authenticated actor. Expose it through a read-only authenticated API
  endpoint and a Settings timeline. Keep full destinations, keys, passwords,
  and tokens out of the history response and logs.
