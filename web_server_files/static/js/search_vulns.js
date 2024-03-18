
var curVulnData = {}, onlyShowCVEs = null;
var exploit_url_show_max_length = 52, exploit_url_show_max_length_md = 42;
var ignoreGeneralCpeVulns = false, onlyShowEDBExploits = false;
var showSingleVersionVulns = false, isGoodCpe = true, showTableFiltering = false;
var noVulnsFoundHtml = '<div class="w-full text-center"><h5 class="text-success">No known vulnerabilities could be found.</h5></div>';
var filterCVEDropdownButtonHtml = `<div class="items-center flex-row mb-2 w-full"><button class="btn btn-sm btn-neutral sm:mr-1 md:mr-2 w-14" id="filterCVEsAll" onclick="changeFilterCVEs(this)">All</button><button class="btn btn-sm btn-neutral w-auto" id="filterCVEsNone" onclick="changeFilterCVEs(this)">None</button></div>`;
var iconUnsorted = '<i class="fa-solid fa-sort"></i>';
var iconSortDesc = '<i class="fa-solid fa-sort-down"></i>';
var iconSortAsc = '<i class="fa-solid fa-sort-up"></i>';
var exportIcon = `<i class="fa-solid fa-clipboard"></i>`, exportIconSuccess = `<i class="fa-solid fa-clipboard-check text-success"></i>`;
var curSortColIdx = 1, curSortColAsc = false, searchIgnoreNextKeyup = false;
var doneTypingQueryTimer, queryInput = $('#query'), doneTypingQueryInterval = 600;  //time in ms
var default_theme = 'dim';

function htmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>\&"']/g, function (i) {
        return '&#' + i.charCodeAt(0) + ';';
    });
}

function reduceToEDBUrls(allUrls) {
    var edb_urls = [];
    for (var i = 0; i < allUrls.length; i++) {
        if (allUrls[i].startsWith('https://www.exploit-db.com/exploits/'))
            edb_urls.push(allUrls[i]);
    }
    return edb_urls;
}

function getCurrentVulnsSorted() {
    var vulns = Object.values(curVulnData);
    if (curSortColIdx == 0) {  // CVE-ID
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            }).reverse();

        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln1.cvss) - parseFloat(vuln2.cvss);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln2.cvss) - parseFloat(vuln1.cvss);
            });
        }
    }
    else if (curSortColIdx == 3) {  // Exploits
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                var exploits1 = vuln1.exploits || [];
                var exploits2 = vuln2.exploits || [];

                if (onlyShowEDBExploits) {
                    exploits1 = reduceToEDBUrls(exploits1);
                    exploits2 = reduceToEDBUrls(exploits2);
                }

                return parseInt(exploits1.length) - parseInt(exploits2.length);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                var exploits1 = vuln1.exploits || [];
                var exploits2 = vuln2.exploits || [];

                if (onlyShowEDBExploits) {
                    exploits1 = reduceToEDBUrls(exploits1);
                    exploits2 = reduceToEDBUrls(exploits2);
                }

                return parseInt(exploits2.length) - parseInt(exploits1.length);
            });
        }
    }
}

function createVulnTableRowHtml(idx, vuln) {
    var vuln_row_html = '', uncertain_vuln_class = "";
    var exploits, cvss, cvss_badge_css, exploit_url_show;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))

    if (selectedColumns.length < 1)
        return '';

    if (vuln.vuln_match_reason == "general_cpe" || vuln.vuln_match_reason == "single_higher_version_cpe")
        uncertain_vuln_class = "uncertain-vuln";

    vuln_row_html += `<tr class="${uncertain_vuln_class}">`;

    if (selectedColumns.includes('cve')) {
        vuln_row_html += `<td class="text-nowrap pr-2 relative"><a href="${htmlEntities(vuln["href"])}" target="_blank" style="color: inherit;">${vuln["id"]}&nbsp;&nbsp;<i class="fa-solid fa-up-right-from-square" style="font-size: 0.92rem"></i></a>`;
        if (vuln.vuln_match_reason == "general_cpe")
            vuln_row_html += `<br><center><span data-tooltip-target="tooltip-general-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-general-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability affects the queried software in general and could be a false positive.<div class="tooltip-arrow" data-popper-arrow></div></div></center>`;
        else if (vuln.vuln_match_reason == "single_higher_version_cpe")
            vuln_row_html += `<br><center><span data-tooltip-target="tooltip-general-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-general-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability affects only a single higher version of the product and could be a false positive.<div class="tooltip-arrow" data-popper-arrow></div></div></center>`;
        vuln_row_html += "</td>";
    }

    if (selectedColumns.includes('cvss')) {
        var cvss_vector = vuln.cvss_vec;
        if (!cvss_vector.startsWith('CVSS'))
            cvss_vector = "CVSS:2.0/" + cvss_vector;

        cvss = parseFloat(vuln.cvss);
        if (cvss >= 9.0)
            cvss_badge_css = "badge-critical";
        else if (cvss < 9.0 && cvss >= 7.0)
            cvss_badge_css = "badge-high";
        else if (cvss < 7.0 && cvss >= 4.0)
            cvss_badge_css = "badge-medium";
        else if (cvss < 4.0 && cvss >= 0.1)
            cvss_badge_css = "badge-low";
        vuln_row_html += `<td class="text-nowrap"><div class="dropdown dropdown-hover"><div class="badge p-1.5 border-none badge-cvss ${cvss_badge_css} text-center ${uncertain_vuln_class}" tabindex="0">${vuln["cvss"]}&nbsp;(v${vuln["cvss_ver"]})</div><div tabindex="0" class="dropdown-content menu m-0 p-1 shadow bg-base-300 rounded-box"><div class="btn btn-ghost btn-xs" onclick="copyToClipboardCVSS(this)"><span><span><i class="fa-solid fa-clipboard"></i></span>&nbsp;&nbsp;<b>${cvss_vector}</b></span></div></div></div></td>`;
    }

    if (selectedColumns.includes('descr')) {
        vuln_row_html += `<td>${htmlEntities(vuln["description"])}</td>`;
    }

    if (selectedColumns.includes('expl')) {
        exploits = [];
        if (vuln.exploits !== undefined) {
            for (var j = 0; j < vuln.exploits.length; j++) {
                if (onlyShowEDBExploits && !vuln.exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vuln.exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length - 2) + '...';
                }
                exploits.push(`<a href="${vuln.exploits[j].replace('"', '&quot;')}" target="_blank" style="color: inherit;">${htmlEntities(exploit_url_show)}</a>`);
            }
        }
        vuln_row_html += `<td class="text-nowrap">${exploits.join("<br>")}</td>`;
    }

    vuln_row_html += "</tr>";
    return vuln_row_html;
}

function renderSearchResults(reloadFilterDropdown) {
    var sortIconCVEID = iconUnsorted, sortFunctionCVEID = "reorderVulns(0, false)";
    var sortIconCVSS = iconUnsorted, sortFunctionCVSS = "reorderVulns(1, false)";
    var sortIconExploits = iconUnsorted, sortFunctionExploits = "reorderVulns(3, false)";

    // retrieve and sort vulns
    var vulns = getCurrentVulnsSorted();
    if (curSortColIdx == 0) {  // CVE-ID
        if (curSortColAsc) {
            sortIconCVEID = iconSortAsc;
            sortFunctionCVEID = "reorderVulns(0, false)";
        }
        else {
            sortIconCVEID = iconSortDesc;
            sortFunctionCVEID = "reorderVulns(0, true)";
        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            sortIconCVSS = iconSortAsc;
            sortFunctionCVSS = "reorderVulns(1, false)";
        }
        else {
            sortIconCVSS = iconSortDesc;
            sortFunctionCVSS = "reorderVulns(1, true)";
        }
    }
    else if (curSortColIdx == 3) {  // Exploits
        if (curSortColAsc) {
            sortIconExploits = iconSortAsc;
            sortFunctionExploits = "reorderVulns(3, false)";
        }
        else {
            sortIconExploits = iconSortDesc;
            sortFunctionExploits = "reorderVulns(3, true)";
        }
    }

    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    if (selectedColumns.length < 1) {
        $("#vulns").html('');
        return false;
    }
    
    vulns_html = '<table class="table table-sm my-table-zebra table-rounded">';
    vulns_html += '<thead class="bg-base-300">';
    vulns_html += '<tr>'
    if (selectedColumns.includes('cve')) {
        vulns_html += `<th onclick="${sortFunctionCVEID}" style="white-space: nowrap;">CVE-ID&nbsp;&nbsp;${sortIconCVEID}</th>`;
    }
    if (selectedColumns.includes('cvss')) {
        vulns_html += `<th onclick="${sortFunctionCVSS}" style="white-space: nowrap;">CVSS&nbsp;&nbsp;${sortIconCVSS}</th>`;
    }
    if (selectedColumns.includes('descr')) {
        vulns_html += '<th>Description</th>'
    }
    if (selectedColumns.includes('expl')) {
        vulns_html += `<th onclick="${sortFunctionExploits}" style="white-space: nowrap;">Exploits&nbsp;&nbsp;${sortIconExploits}</th>`;
    }
    vulns_html += "</tr></thead>";
    vulns_html += "<tbody>";

    var filter_vulns_html = filterCVEDropdownButtonHtml, has_vulns = false;
    for (var i = 0; i < vulns.length; i++) {
        // create row in table
        if (ignoreGeneralCpeVulns && vulns[i].vuln_match_reason == "general_cpe")
            continue;
        else if (!showSingleVersionVulns && vulns[i].vuln_match_reason == "single_higher_version_cpe")
            continue;

        has_vulns = true;
        var checked_html = "";
        if (!showTableFiltering || onlyShowCVEs == null || onlyShowCVEs.includes(vulns[i].id)) {
            vulns_html += createVulnTableRowHtml(i, vulns[i]);
            checked_html = 'checked="checked"';
        }

        // add CVE to filter
        filter_vulns_html += `<div class="form-control filter-cves"><label class="label cursor-pointer py-1 gap-4"><span class="label-text text-nowrap">${vulns[i]["id"]}</span><input type="checkbox" class="checkbox" onclick="changeFilterCVEs()" ${checked_html} /></label></div>`;
    }
    vulns_html += "</tbody></table>";
    if (has_vulns)
        $("#vulns").html(vulns_html);

    if (reloadFilterDropdown)
        $('#filterCVEsDropdown').html(filter_vulns_html);  // set CVE filter HTML
    $('#exportMarkdownIcon').html(exportIcon);
    $('#exportCSVIcon').html(exportIcon);

    initFlowbite();
    fixDropdownClicking();

    return has_vulns;
}

function createVulnsMarkDownTable() {
    var selectedVulns = onlyShowCVEs;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    var vulns = getCurrentVulnsSorted();
    var vulns_md = "";
    var has_exploits = false, cur_vuln_has_exploits = false;
    var exploit_url_show;

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (selectedColumns.length > 0) {
        var table_row1 = "|", table_row2 = "|";
        selectedColumns.forEach(column => {
            if (column == 'cve') {
                table_row1 += 'CVE|';
                table_row2 += ':---:|';
            }
            else if (column == 'cvss') {
                table_row1 += 'CVSS|';
                table_row2 += ':---:|';
            }
            else if (column == 'descr') {
                table_row1 += 'Description|';
                table_row2 += ':---|';
            }
            else if (column == "epxl" && has_exploits) {
                table_row1 += 'Exploits|';
                table_row2 += ':---|';
            }
        })
        vulns_md = table_row1 + '\n' + table_row2 + '\n';
    }
    else {
        if (has_exploits) {
            vulns_md = '|CVE|CVSS|Description|Exploits|\n';
            vulns_md += '|:---:|:---:|:---|:---|\n';
        }
        else {
            vulns_md = '|CVE|CVSS|Description|\n';
            vulns_md += '|:---:|:---:|:---|\n';
        }
    }

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;

        cur_vuln_has_exploits = false;
        vulns_md += '|';
        if (selectedColumns.length < 1 || selectedColumns.includes("cve"))
            vulns_md += `[${vulns[i]["id"]}](${htmlEntities(vulns[i]["href"])})|`
        if (selectedColumns.length < 1 || selectedColumns.includes("cvss"))
            vulns_md += `${vulns[i]["cvss"]}&nbsp;(v${vulns[i]["cvss_ver"]})|`;
        if (selectedColumns.length < 1 || selectedColumns.includes("descr")) {
            var description = htmlEntities(vulns[i]["description"].trim());
            description = description.replaceAll('\n', '<br>');
            description = description.replaceAll('|', '&#124;');
            vulns_md += `${description}|`;
        }

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedColumns.length < 1 || selectedColumns.includes('expl'))) {
            for (var j = 0; j < vulns[i].exploits.length; j++) {
                if (onlyShowEDBExploits && !vulns[i].exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vulns[i].exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length_md) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length_md - 2) + '...';
                }
                vulns_md += `[${htmlEntities(exploit_url_show)}](${vulns[i].exploits[j]})<br>`;
                cur_vuln_has_exploits = true;
            }
            if (cur_vuln_has_exploits) {
                vulns_md = vulns_md.substring(0, vulns_md.length - 4);  // remove last <br>
                vulns_md += "|";
            }
            else if (has_exploits)
                vulns_md += "|";
        }
        else if (has_exploits && (selectedColumns.length < 1 || selectedColumns.includes('expl')))
            vulns_md += "|";

        vulns_md += '\n'
    }

    return vulns_md;
}

function createVulnsCSV() {
    var selectedVulns = onlyShowCVEs;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    var vulns = getCurrentVulnsSorted();
    var vulns_csv = "";
    var has_exploits = false;

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (selectedColumns.length > 0) {
        selectedColumns.forEach(column => {
            if (column == "cve")
                vulns_csv += 'CVE,';
            else if (column == "cvss")
                vulns_csv += 'CVSS,';
            else if (column == "descr")
                vulns_csv += 'Description,';
            else if (column == "expl" && has_exploits)
                vulns_csv += 'Exploits,';
        })
        vulns_csv = vulns_csv.slice(0, -1) + '\n';
    }
    else {
        if (has_exploits)
            vulns_csv = 'CVE,CVSS,Description,Exploits\n';
        else
            vulns_csv = 'CVE,CVSS,Description\n';
    }

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;

        if (selectedColumns.length < 1 || selectedColumns.includes('cve'))
            vulns_csv += `${vulns[i]["id"]},`
        if (selectedColumns.length < 1 || selectedColumns.includes('cvss'))
            vulns_csv += `${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]}),`;
        if (selectedColumns.length < 1 || selectedColumns.includes('descr'))
            vulns_csv += `"${vulns[i]["description"].replaceAll('"', '""')}",`;

        if (vulns_csv.length > 0 && (!has_exploits || (selectedColumns.length > 0 && !selectedColumns.includes('expl'))))
            vulns_csv = vulns_csv.slice(0, -1);

        if (has_exploits && vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedColumns.length < 1 || selectedColumns.includes('expl'))) {
            if (onlyShowEDBExploits)
                vulns_csv += `"${reduceToEDBUrls(vulns[i].exploits).join(", ")}"`;
            else
                vulns_csv += `"${vulns[i].exploits.join(", ")}"`;
        }
        vulns_csv += '\n'
    }

    return vulns_csv;
}


function buildTextualReprFromCPE(cpe) {
    var product_title, cpe_parts, product_type, cpe_condition = '';
    cpe_parts = cpe.split(":");
    cpe_condition = '';

    if (cpe_parts[2] == 'a')
        product_type = 'Software';
    else if (cpe_parts[2] == 'o')
        product_type = 'Operating System';
    else if (cpe_parts[2] == 'h')
        product_type = 'Hardware';

    cpe_parts[3] = cpe_parts[3][0].toUpperCase() + cpe_parts[3].substring(1);
    cpe_parts[4] = cpe_parts[4][0].toUpperCase() + cpe_parts[4].substring(1);
    if (cpe_parts[4].startsWith(cpe_parts[3]))
        cpe_parts[4] = cpe_parts[4].substring(cpe_parts[3].length).trim();
    if (cpe_parts[4].startsWith('_'))
        cpe_parts[4] = cpe_parts[4].substring(1);

    product_title = cpe_parts[3].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
    if (cpe_parts[4] && cpe_parts[4] != cpe_parts[3])
        product_title += cpe_parts[4].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';

    if (cpe_parts[5] && cpe_parts[5] != '-' && cpe_parts[5] != '*')
        product_title += cpe_parts[5] + ' ';

    if (cpe_parts[6] && cpe_parts[6] != '-' && cpe_parts[6] != '*')
        product_title += cpe_parts[6] + ' ';

    cpe_parts.slice(7).forEach(cpe_part => {
        if (cpe_part && cpe_part != '-' && cpe_part != '*') {
            cpe_part = cpe_part[0].toUpperCase() + cpe_part.substring(1);
            cpe_condition += cpe_part.split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
        }
    });

    product_title = product_title.trim();
    cpe_condition = cpe_condition.trim();

    if (cpe_condition)
        return product_type + ': ' + product_title + ' ' + '[' + cpe_condition + ']';

    return product_type + ': ' + product_title
}


function searchVulns() {
    clearTimeout(doneTypingQueryTimer);
    var query = $('#query').val();
    if (query === undefined)
        query = '';
    var queryEnc = encodeURIComponent(query);
    var url_query = "query=" + queryEnc;
    var new_url = window.location.pathname + '?query=' + queryEnc;

    if (!isGoodCpe) {
        url_query += "&is-good-cpe=false";
        new_url += '&is-good-cpe=false';
    }
    url_query += "&include-single-version-vulns=true";  // false is default in backend

    isGoodCpe = true;  // reset for subsequent query that wasn't initiated via URL

    history.pushState({}, null, new_url);  // update URL
    $("#buttonSearchVulns").html('<span class="loading loading-spinner"></span> Searching');
    $("#buttonSearchVulns").addClass("btn-disabled");
    $("#buttonFilterCVEs").addClass("btn-disabled");
    $("#buttonManageColumns").addClass("btn-disabled");
    $("#buttonExportResults").addClass("btn-disabled");
    $('#cpeSuggestions').addClass("hidden");
    $('#cpeSuggestions').html();
    searchIgnoreNextKeyup = true;

    $("#search-display").html("");
    $("#related-queries-display").html("");
    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curSortColIdx = 1;
    curSortColAsc = false;
    curVulnData = {};

    $.get({
        url: "/search_vulns",
        data: url_query,
        success: function (vulns) {
            var search_display_html = "", related_queries_html = '', queryError = false;
            if (typeof Object.values(vulns)[0] !== "object") {
                search_display_html = `<h5 class="text-error text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                queryError = true;
            }
            else {
                vulns = Object.values(vulns)[0]
                cpe = vulns['cpe'];
                if (cpe != undefined) {
                    curVulnData = vulns['vulns'];
                    cpe = cpe.replaceAll('/', ' / ');
                    search_display_html = `<div class="row mt-2"><div class="col text-center text-info"><h5 style="font-size: 1.05rem;">${htmlEntities(query)} (${htmlEntities(cpe)})</h5></div></div>`;
                }
                else {
                    search_display_html = `<h5 class="text-error w-full text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                    queryError = true;
                }

                if (vulns.hasOwnProperty('pot_cpes') && vulns["pot_cpes"].length > 0) {
                    var related_queries_html_li = "";
                    for (var i = 0; i < vulns["pot_cpes"].length; i++) {
                        if (cpe == null || !cpe.includes(vulns["pot_cpes"][i][0]))
                            related_queries_html_li += `<li><a href="${window.location.pathname}?query=${encodeURIComponent(htmlEntities(vulns["pot_cpes"][i][0]))}&is-good-cpe=false">${htmlEntities(vulns["pot_cpes"][i][0])} &nbsp; &nbsp;(${htmlEntities(buildTextualReprFromCPE(vulns["pot_cpes"][i][0]))})</a></li>`
                    }

                    if (related_queries_html_li != "") {
                        related_queries_html = `<div class="divider divider-info text-lg">Related Queries</div>`;
                        related_queries_html += `<div class="grid place-items-center">`;
                        related_queries_html += `<ul class="list-disc text-left">`;
                        related_queries_html += related_queries_html_li;
                        related_queries_html += `</ul></div>`;
                    }
                }
            }

            $("#search-display").html(search_display_html);
            onlyShowCVEs = null;
            var hasVulns = renderSearchResults(true);
            if (!hasVulns && !queryError)
                $('#vulns').html(noVulnsFoundHtml);
                
            $("#related-queries-display").html(related_queries_html);
            $("#buttonSearchVulns").removeClass("btn-disabled");
            $("#buttonFilterCVEs").removeClass("btn-disabled");
            $("#buttonManageColumns").removeClass("btn-disabled");
            $("#buttonExportResults").removeClass("btn-disabled");
            $("#buttonSearchVulns").html('<i class="fa-solid fa-magnifying-glass"></i> Search Vulns');
            currentlySearchingVulns = false;
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;

            $("#vulns").html(`<h5 class="text-error w-full text-center">${htmlEntities(errorMsg)}</h5>`);
            $("#buttonSearchVulns").removeClass("btn-disabled");
            $("#buttonFilterCVEs").removeClass("btn-disabled");
            $("#buttonManageColumns").removeClass("btn-disabled");
            $("#buttonExportResults").removeClass("btn-disabled");
            $("#buttonSearchVulns").html('<i class="fa-solid fa-magnifying-glass"></i> Search Vulns');
            currentlySearchingVulns = false;
        }
    });
}

function reorderVulns(sortColumnIdx, asc) {
    curSortColIdx = sortColumnIdx;
    curSortColAsc = asc;
    var hasVulns = renderSearchResults(true);
    if (!hasVulns)
        $('#vulns').html(noVulnsFoundHtml);
}

function copyToClipboardMarkdownTable() {
    navigator.clipboard.writeText(createVulnsMarkDownTable());
    $('#exportMarkdownIcon').html(exportIconSuccess);
}

function copyToClipboardCSV() {
    navigator.clipboard.writeText(createVulnsCSV());
    $('#exportCSVIcon').html(exportIconSuccess);
}

function copyToClipboardCVSS(cvssClipboardButton) {
    navigator.clipboard.writeText($(cvssClipboardButton).find("b").text());
    $(cvssClipboardButton).find('span').find('span').addClass('text-success');
    $(cvssClipboardButton).find('span').find('span').html('<i class="fa-solid fa-clipboard-check"></i>');
    document.activeElement.blur();
}

function changeTheme(themeElement) {
    var theme;
    if (themeElement != null)
        theme = themeElement.id.split('-').slice(-1)[0];
    else {
        theme = default_theme;
        themeElement = $('#theme-option-' + default_theme);
    }
    document.documentElement.setAttribute("data-theme", theme);
    $('#theme-selector').find('li a').removeClass('active');
    $('#theme-selector').find('li a span').remove();
    $(themeElement).find('a').addClass('active');
    $(themeElement).find('a').append('<span class="text-right"><i class="fa-solid fa-check"></i></span>');
    localStorage.setItem("theme", theme);
}

function changeSearchConfig(configElement) {
    var settingEnabled = false, settingEnabledStr = "false";
    if (configElement.checked) {
        settingEnabled = true;
        settingEnabledStr = "true";
    }

    if (configElement.id == "generalVulnsConfig") {
        ignoreGeneralCpeVulns = settingEnabled;
        localStorage.setItem("ignoreGeneralCpeVulns", settingEnabledStr);
    }
    else if (configElement.id == "onlyEdbExploitsConfig") {
        onlyShowEDBExploits = settingEnabled;
        localStorage.setItem("onlyShowEDBExploits", settingEnabledStr);
    }
    else if (configElement.id == "showSingleVersionVulnsConfig") {
        showSingleVersionVulns = settingEnabled;
        localStorage.setItem("showSingleVersionVulns", settingEnabledStr);
    }
    else if (configElement.id == "showTableFilteringConfig") {
        showTableFiltering = settingEnabled;
        localStorage.setItem("showTableFiltering", settingEnabledStr);
    }

    if (!$.isEmptyObject(curVulnData)) {
        var hasVulns = renderSearchResults(true);
        if (!hasVulns)
            $('#vulns').html(noVulnsFoundHtml);
    }
}

function changeColumnConfig(columnElement) {
    var vulnTableColumns = [], allCheckType = null;

    if (columnElement.id == 'showColumnAll')
        allCheckType = true
    else if (columnElement.id == 'showColumnNone')
        allCheckType = false

    if (allCheckType != null) {
        columnCheckboxIDs = ['showColumnCVEID', 'showColumnCVSS', 'showColumnDescription', 'showColumnExploits'];
        columnCheckboxIDs.forEach(function(columnCheckboxID) {
            $('#' + columnCheckboxID)[0].checked = allCheckType;
        });
    }

    if ($('#showColumnCVEID')[0].checked)
        vulnTableColumns.push('cve');
    if ($('#showColumnCVSS')[0].checked)
        vulnTableColumns.push('cvss');
    if ($('#showColumnDescription')[0].checked)
        vulnTableColumns.push('descr');
    if ($('#showColumnExploits')[0].checked)
        vulnTableColumns.push('expl');

    localStorage.setItem('vulnTableColumns', JSON.stringify(vulnTableColumns));

    if (!$.isEmptyObject(curVulnData) && showTableFiltering)
        renderSearchResults();
}

function changeFilterCVEs(filterCVEsButton) {
    onlyShowCVEs = [];
    var allOrNone = '';

    if (filterCVEsButton != null) {
        if(filterCVEsButton.id == 'filterCVEsNone')
            allOrNone = 'none';
        else {
            onlyShowCVEs = null;
            allOrNone = 'all';
        }
    }

    $('.filter-cves').each(function(i, filterCVEDiv) {
        filterCVEDiv = $(filterCVEDiv);
        if (allOrNone == 'none')
            filterCVEDiv.find('.checkbox')[0].checked = false;
        else if (allOrNone == 'all')
            filterCVEDiv.find('.checkbox')[0].checked = true;

        if (onlyShowCVEs != null && filterCVEDiv.find('.checkbox')[0].checked)
            onlyShowCVEs.push(filterCVEDiv.find('.label-text').text().trim());
    });

    if (!$.isEmptyObject(curVulnData) && showTableFiltering)
        renderSearchResults();
}

function setupConfigFromLocalstorage() {
    if (localStorage.getItem('ignoreGeneralCpeVulns') === null) {
        localStorage.setItem('ignoreGeneralCpeVulns', 'false');
    }
    if (localStorage.getItem('onlyShowEDBExploits') === null) {
        localStorage.setItem('onlyShowEDBExploits', 'false');
    }
    if (localStorage.getItem('showSingleVersionVulns') === null) {
        localStorage.setItem('showSingleVersionVulns', 'false');
    }
    if (localStorage.getItem('showTableFiltering') === null) {
        localStorage.setItem('showTableFiltering', 'true');
    }
    
    if (localStorage.getItem('ignoreGeneralCpeVulns') == 'true') {
        ignoreGeneralCpeVulns = true;
        document.getElementById("generalVulnsConfig").checked = true;
    }
    if (localStorage.getItem('onlyShowEDBExploits') == 'true') {
        onlyShowEDBExploits = true;
        document.getElementById("onlyEdbExploitsConfig").checked = true;
    }
    if (localStorage.getItem('showSingleVersionVulns') == 'true') {
        showSingleVersionVulns = true;
        document.getElementById("showSingleVersionVulnsConfig").checked = true;
    }
    if (localStorage.getItem('showTableFiltering') == 'true') {
        showTableFiltering = true;
        document.getElementById("showTableFilteringConfig").checked = true;
    }
    
    if (localStorage.getItem('vulnTableColumns') === null) {
        localStorage.setItem('vulnTableColumns', '["cve", "cvss", "descr", "expl"]');
    }
    var vulnTableColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))

    if (vulnTableColumns.includes('cve'))
        document.getElementById("showColumnCVEID").checked = true;
    if (vulnTableColumns.includes('cvss'))
        document.getElementById("showColumnCVSS").checked = true;
    if (vulnTableColumns.includes('descr'))
        document.getElementById("showColumnDescription").checked = true;
    if (vulnTableColumns.includes('expl'))
        document.getElementById("showColumnExploits").checked = true;

}

function initQuery() {
    if (location.search !== '' && location.search !== '?') {
        var url = new URL(document.location.href);
        var params = new URLSearchParams(url.search);
        var init_query = params.get('query');
        if (init_query !== null)
            $('#query').val(htmlEntities(init_query));

        var is_good_cpe = params.get('is-good-cpe');
        if (String(is_good_cpe).toLowerCase() === "false")
            isGoodCpe = false;

        if (init_query !== null)
            $("#buttonSearchVulns").click();
    }
}

function fixDropdownClicking() {
    $('.dropdown').find('.btn:first').on('mousedown', function(event) {
        var closestDropdown = document.activeElement.closest('.dropdown') 
        if (closestDropdown !== null && closestDropdown == event.target.closest('.dropdown')) {
            event.preventDefault();
            document.activeElement.blur();
        }
    });
}

function backToTop() {
    window.scroll({ top: 0, behavior: "smooth" });
}

function doneTypingQuery () {
    // user paused or finished typing query --> retrieve and show CPE suggestions
    $('#cpeSuggestions').html('<div class="loading loading-spinner"></div>');
    $('#cpeSuggestions').removeClass('hidden');
    $("#buttonSearchVulns").addClass("btn-disabled");

    var query = $('#query').val();
    if (query === undefined)
        query = '';

    var queryEnc = encodeURIComponent(query);
    var url_query = "query=" + queryEnc;

    $.get({
        url: "/cpe_suggestions",
        data: url_query,
        success: function (cpeInfos) {
            if (!Array.isArray(cpeInfos)) {
                console.log(cpeInfos)
            }
            else if (cpeInfos.length > 0) {
                var dropdownContent = '<ul class="menu menu-md p-1 bg-base-200 rounded-box">';
                cpeInfos.forEach(function (cpeInfo) {
                    dropdownContent += `<li><a class="text-nowrap" href="${window.location.pathname}?query=${encodeURIComponent(htmlEntities(cpeInfo[0]))}&is-good-cpe=false">${htmlEntities(cpeInfo[0])}</a></li>`
                });
                dropdownContent += '</ul>';
                $('#cpeSuggestions').html(dropdownContent);
            }
            else {
                $('#cpeSuggestions').html("No results found");
            }
            $("#buttonSearchVulns").removeClass("btn-disabled");
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;
            console.log(errorMsg);
            $("#buttonSearchVulns").removeClass("btn-disabled");
        }
    })
}

function closeCPESuggestions() {
    $('#cpeSuggestions').addClass('hidden');
}


/* init */

// enables the user to press return on the query text field to make the query
$("#query").keypress(function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == "13" && !$("#buttonSearchVulns").hasClass("btn-disabled"))
        $("#buttonSearchVulns").click();
});

// set theme
document.addEventListener('DOMContentLoaded', function() {
    if (localStorage.getItem('theme') !== null)
        changeTheme($('#theme-option-' + localStorage.getItem('theme'))[0]);
    else
        changeTheme();
    document.body.classList.remove('hidden');
});

// fix dropdown open buttons to close again on click
fixDropdownClicking();

// setup configuration from LocalStorage
setupConfigFromLocalstorage();

// check for existing query in URL and insert its parameters
initQuery();

// register scroll events for back to top button to display or not
var toTopButton = $("#toTopButton");
window.onscroll = function() {
    if (document.body.scrollTop > 750 || document.documentElement.scrollTop > 750)
        toTopButton.removeClass("hidden");
    else
        toTopButton.addClass("hidden");
};

// register timers and functions for query input field
// on keyup, start the countdown to register finished typing
queryInput.on('keyup', function () {
    clearTimeout(doneTypingQueryTimer);
    if (!searchIgnoreNextKeyup)
        doneTypingQueryTimer = setTimeout(doneTypingQuery, doneTypingQueryInterval);
    searchIgnoreNextKeyup = false;
});

// on keydown, clear the typing countdown and hide dropdown
queryInput.on('keydown', function () {
    clearTimeout(doneTypingQueryTimer);
    $('#cpeSuggestions').addClass("hidden");
    $('#cpeSuggestions').html();
});

// focus on query input field at the beginning
window.onload = function () {
    queryInput.focus();
}
