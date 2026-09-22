package packs

import "testing"

// Every rejected card row is Luhn-valid and was redacted by the old card rule on a real archive;
// its comment names the check that now rejects it.
func TestPIIRulesFindIdentifiersAndRejectLookalikes(t *testing.T) {
	hit := func(in, want string) probe { return probe{in, want} }
	miss := func(in string) probe { return probe{in: in} }
	cases := map[string][]probe{
		"pesel": {
			hit("pesel 44051401359 ok", "44051401359"),
			miss("44051401358"), // check digit
			miss("44991401351"), // month 99 occurs in no century encoding
		},
		"iban": {
			hit("iban DE89370400440532013000 ok", "DE89370400440532013000"),
			hit("GB82WEST12345698765432", "GB82WEST12345698765432"),
			miss("GB82WEST12345698765433"),
		},
		"email": {
			hit("mail jane@example.com now", "jane@example.com"),
			hit("<a.b+tag@sub.example.co.uk>", "a.b+tag@sub.example.co.uk"),
		},
		"card-pan": {
			// Test PANs from the card networks' published sets, in every notation.
			hit("pay with 4111111111111111 now", "4111111111111111"),
			hit("card: 4111 1111 1111 1111", "4111 1111 1111 1111"),
			hit("card 4111-1111-1111-1111.", "4111-1111-1111-1111"),
			hit("old visa 4222222222222", "4222222222222"),
			hit("amex 378282246310005", "378282246310005"),
			hit("amex 3782 822463 10005", "3782 822463 10005"),
			hit("mc 5555555555554444", "5555555555554444"),
			hit("mc 2223003122003222", "2223003122003222"),
			hit("discover 6011111111111117", "6011111111111117"),
			hit("diners 30569309025904", "30569309025904"),
			hit("up 6200000000000005", "6200000000000005"),
			hit("the card is 4111111111111111.", "4111111111111111"),
			hit("4111111111111111", "4111111111111111"),
			miss("4111111111111112"), // Luhn
			// Decimal fractions and integer parts: the guard, not the checksum.
			miss("rmse: 0.4712949612297219 after 40 epochs"),
			miss("coefficient .4712949612297219 stored"),
			miss("value 4111111111111111.25 overflows"),
			// Datestamp ids: 8-6 fails grouping, contiguous fails the issuer window.
			miss("run 20260619-100853 failed"),
			miss("tag taiga-20260619100853 pushed"),
			// Epoch milliseconds start 17 or 18, outside every issuer range.
			miss("tool-results/webfetch-1783361082810-3jalbx.pdf"),
			miss("startedAt 1783361082810 elapsed 4162"),
			// A 19-digit LinkedIn activity id: the issuer check rejects the 7.
			miss("linkedin.com/posts/x_activity-7382019465738291045-AbCd"),
			// UUID digit chunks: card grouping, issuer 1.
			miss("sessionId 1111-1111-1111-1111 resumed"),
			// Uniform separator with the wrong grouping, then mixed separators.
			miss("seats 411 1111 1111 11111 booked"),
			miss("ref 4111 1111-1111 1111 logged"),
			// A 14-digit SIRET written 3-3-3-5.
			miss("SIRET 552 100 554 00031 registered"),
		},
	}
	for id, probes := range cases {
		checkProbes(t, ruleByID(t, PIICore, id), probes)
	}
}
