# @TEST-EXEC: bro -NN Bro::Lognorm | sed -e 's/version.*)/version)/g' > output
# @TEST-EXEC: btest-diff output
