# @TEST-EXEC: zeek -NN Zeek::Lognorm | sed -e 's/version.*)/version)/g' > output
# @TEST-EXEC: btest-diff output
