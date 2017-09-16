#include "crow.h"
#include <string>

int main() {
    crow::SimpleApp app;

    TEMPLATE_FILERESPONSE_START
    CROW_ROUTE(app, "/"TEMPLATE_URI)([]() {
        return std::string(TEMPLATE_CONTENT, TEMPLATE_LENGTH);
    });

    TEMPLATE_FILERESPONSE_END
    TEMPLATE_FILERESPONSE_LIST

    std::string HACK_SOURCECODE("NOT FOUND");
    CROW_ROUTE(app, "/tailing.cc")([&](const crow::request &/* req */, crow::response &res) {
        res.add_header("Content-Disposition", "attachment; filename=tailing.cc");
        res.write(HACK_SOURCECODE);
        res.end();
    });

    app.port(18080).multithreaded().run();
    return 0;
}
