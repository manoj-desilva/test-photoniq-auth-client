#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <photoniq_auth_client/AuthValidator.h>


using namespace auth;
using namespace testing;

//class TestConnection: public Connection {
//public:
//  TestConnection(boost::asio::ip::tcp::socket&& socket, boost::asio::io_context& context):
//    Connection(std::move(socket), context) {}
//  void run(boost::asio::yield_context& yield) {}
//};

class AuthTestFixture : public Test {
public:
  void SetUp() {
  }
  void TearDown() {
  }
};

//TEST_F(ConnectionFixture, CreateConnectionAndCheckItsNameLength) {
//  boost::asio::io_context context;
//  boost::asio::ip::tcp::socket socket(context);
//  TestConnection connection(std::move(socket), context);
//  EXPECT_GE(connection.name().length(), 0);
//}

TEST_F(AuthTestFixture, BasicAuthTest) {
  AuthValidator validator;
}
