#include "crow.h"
#include <cstdlib>
#include <string>

int main(int argc, char *argv[]) {
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

    int port = 8888;
    if (argc > 1)
        port = atoi(argv[1]);
    app.port(port).multithreaded().run();
    return 0;
}
