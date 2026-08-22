#include "httplib.h"
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>

struct FileResponse {
    const char *content_type;
    const char *etag;
    const char *last_modified;
    std::string content;
};

typedef std::map<std::string, FileResponse> FileMap;

static void add_file(FileMap &files, const std::string &uri, const char *content_type,
                     const char *etag, const char *last_modified,
                     const char *content, std::size_t length) {
    FileResponse &file = files[uri];
    file.content_type = content_type;
    file.etag = etag;
    file.last_modified = last_modified;
    file.content.assign(content, length);
}

int main(int argc, char *argv[]) {
    FileMap files;

    TEMPLATE_FILERESPONSE_START
    add_file(files, "/" TEMPLATE_URI, TEMPLATE_CONTENT_TYPE, TEMPLATE_ETAG, TEMPLATE_LAST_MODIFIED, TEMPLATE_CONTENT_STR, TEMPLATE_LENGTH);
    TEMPLATE_FILERESPONSE_END
    TEMPLATE_FILERESPONSE_LIST

    std::string HACK_SOURCECODE("NOT FOUND");

    httplib::Server app;
    // One catch-all route: a route per file would make cpp-httplib compile a
    // std::regex for every URI, since a path like "/index.html" contains regex
    // metacharacters.
    app.Get(".*", [&](const httplib::Request &req, httplib::Response &res) {
        if (req.path == "/tailing.cc") {
            res.set_header("Content-Disposition", "attachment; filename=tailing.cc");
            res.set_content(HACK_SOURCECODE, "text/plain; charset=UTF-8");
            return;
        }
        FileMap::const_iterator it = files.find(req.path);
        if (it == files.end()) {
            res.status = 404;
            res.set_content("Not Found", "text/plain; charset=UTF-8");
            return;
        }
        res.set_header("ETag", it->second.etag);
        res.set_header("Last-Modified", it->second.last_modified);
        res.set_content(it->second.content, it->second.content_type);
    });

    int port = 8888;
    if (argc > 1)
        port = atoi(argv[1]);
    if (!app.listen("0.0.0.0", port)) {
        std::fprintf(stderr, "cannot listen on port %d\n", port);
        return 1;
    }
    return 0;
}
