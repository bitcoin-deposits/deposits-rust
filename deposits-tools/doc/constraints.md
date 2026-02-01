wallet SHOULD:
  verify that make_invoice includes a cosignature by the ledger channel partner
  provide preimage as proof of fraud when an invoice is paid without being credited

wallet MUST:
  provide a scriptpubkey signature in pay_invoice

channel partner MUST verify that:
  receivingcreditpayment doesn't exceed ledger reserves or declared collateral
  sendinglockpayment includes scriptpubkey signature
  sendingfulfillpayment includes scriptpubkey signature and invoice preimage
  reservesincrease doesn't increase reserves past channel balance
  reservesdecrease doesn't fall below ledger requirement
  maintenancefeecollect does not occur ahead of schedule
  
quorum member MUST verify that:
  collateralincrease doesn't exceed commited reserves
  collateraldecrease doesn't happen in the same reporting period as collateralincrease
