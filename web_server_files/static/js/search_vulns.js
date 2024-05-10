
var curVulnData = {}, curEOLData = {}, onlyShowCVEs = null;
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
var curSelectedCPESuggestion = -1, suggestedQueriesJustOpened = false;


function htmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>\&"']/g, function (c) {
        return '&#' + c.charCodeAt(0) + ';';
    });
}

function escapeMarkdownSimple(text) {
    return text.replace(/[\\|*_\[\]`]/g, function (c) {
        return '\\' + c;
    });
}

function escapeCSV(text) {
    text = text.replaceAll('"', '""');
    if (['=', '+', '-', '@'].some(c => text.startsWith(c)))
        text = "'" + text;
    if (text.includes(',') || text.includes('"'))
        text = `"${text}"`;
    return text;
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
    var vuln_row_html = '', vuln_style_class = '', vuln_flag_html = '';
    var exploits, cvss, cvss_badge_css, exploit_url_show;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))

    if (selectedColumns.length < 1)
        return '';

    if (vuln.vuln_match_reason == "general_cpe" || vuln.vuln_match_reason == "single_higher_version_cpe")
        vuln_style_class = "uncertain-vuln";
    if (vuln.cisa_known_exploited)
        vuln_style_class += " exploited-vuln";  // overwrites color of uncertain vuln

    vuln_row_html += `<tr class="${vuln_style_class} border-none">`;

    if (selectedColumns.includes('cve')) {
        vuln_row_html += `<td class="text-nowrap whitespace-nowrap pr-2 relative"><a href="${htmlEntities(vuln["href"])}" target="_blank" style="color: inherit;">${vuln["id"]}&nbsp;&nbsp;<i class="fa-solid fa-up-right-from-square" style="font-size: 0.92rem"></i></a>`;

        if (vuln.vuln_match_reason == "general_cpe")
            vuln_flag_html += `<br><center><span class="vuln-flag-icon" data-tooltip-target="tooltip-general-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-general-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability affects the queried software in general and could be a false positive.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        else if (vuln.vuln_match_reason == "single_higher_version_cpe")
            vuln_flag_html += `<br><center><span class="vuln-flag-icon" data-tooltip-target="tooltip-general-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-general-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability affects only a single higher version of the product and could be a false positive.<div class="tooltip-arrow" data-popper-arrow></div></div>`;

        if (vuln.cisa_known_exploited) {
            if (vuln_flag_html)
                vuln_flag_html += `<span class="ml-2 vuln-flag-icon" data-tooltip-target="tooltip-exploit-${idx}" data-tooltip-placement="bottom"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${vuln["id"]}&field_date_added_wrapper=all&sort_by=field_date_added&items_per_page=20" target="_blank"><i class="fa-solid fa-skull text-exploited"></i></a></span><div id="tooltip-exploit-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability has been exploited in the wild according to CISA.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
            else
                vuln_flag_html += `<br><center><span class="ml-2 vuln-flag-icon" data-tooltip-target="tooltip-exploit-${idx}" data-tooltip-placement="bottom"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${vuln["id"]}&field_date_added_wrapper=all&sort_by=field_date_added&items_per_page=20" target="_blank"><i class="fa-solid fa-skull text-exploited"></i></a></span><div id="tooltip-exploit-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability has been exploited in the wild according to CISA.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        }

        if (vuln_flag_html)
            vuln_flag_html += '</center>';

        vuln_row_html += vuln_flag_html + "</td>";
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
        vuln_row_html += `<td class="text-nowrap whitespace-nowrap"><div class="dropdown dropdown-hover"><div class="z-10 badge p-1.5 border-none badge-cvss ${cvss_badge_css} text-center ${vuln_style_class}" tabindex="0">${vuln["cvss"]}&nbsp;(v${vuln["cvss_ver"]})</div><div tabindex="0" class="dropdown-content z-20 menu m-0 p-1 shadow bg-base-300 rounded-box"><div class="btn btn-ghost btn-xs" onclick="copyToClipboardCVSS(this)"><span><span><i class="fa-solid fa-clipboard"></i></span>&nbsp;&nbsp;<b>${cvss_vector}</b></span></div></div></div></td>`;
    }

    if (selectedColumns.includes('descr')) {
        vuln_row_html += `<td class="text-wrap dont-break-out mx-auto">${htmlEntities(vuln["description"])}</td>`;
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
        vuln_row_html += `<td class="text-nowrap whitespace-nowrap">${exploits.join("<br>")}</td>`;
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
    
    vulns_html = '<table class="table table-sm my-table-zebra table-rounded table-auto">';
    vulns_html += '<thead>';
    vulns_html += '<tr>'
    if (selectedColumns.includes('cve')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionCVEID}" style="white-space: nowrap;">CVE-ID&nbsp;&nbsp;${sortIconCVEID}</th>`;
    }
    if (selectedColumns.includes('cvss')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionCVSS}" style="white-space: nowrap;">CVSS&nbsp;&nbsp;${sortIconCVSS}</th>`;
    }
    if (selectedColumns.includes('descr')) {
        vulns_html += '<th class="bg-base-300">Description</th>'
    }
    if (selectedColumns.includes('expl')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionExploits}" style="white-space: nowrap;">Exploits&nbsp;&nbsp;${sortIconExploits}</th>`;
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
        filter_vulns_html += `<div class="form-control filter-cves"><label class="label cursor-pointer py-1 gap-4"><span class="label-text text-nowrap whitespace-nowrap">${vulns[i]["id"]}</span><input type="checkbox" class="checkbox" onclick="changeFilterCVEs()" ${checked_html} /></label></div>`;
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
        if (ignoreGeneralCpeVulns && vulns[i].vuln_match_reason == "general_cpe")
            continue;
        if (!showSingleVersionVulns && vulns[i].vuln_match_reason == "single_higher_version_cpe")
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
            else if (column == "expl" && has_exploits) {
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
        if (ignoreGeneralCpeVulns && vulns[i].vuln_match_reason == "general_cpe")
            continue;
        if (!showSingleVersionVulns && vulns[i].vuln_match_reason == "single_higher_version_cpe")
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

            // try to keep markdown for nicer display sometimes
            if (description.includes("**") || description.split("`").length - 1 > 1) {
                description = description.replaceAll('|', '\\|');
            }
            // otherwise escape most impactful Markdown characters.
            // not every Markdown character is escaped, because this
            // creates issues with some parsers.
            else {
                description = escapeMarkdownSimple(description);
            }

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
        if (ignoreGeneralCpeVulns && vulns[i].vuln_match_reason == "general_cpe")
            continue;
        if (!showSingleVersionVulns && vulns[i].vuln_match_reason == "single_higher_version_cpe")
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
        if (ignoreGeneralCpeVulns && vulns[i].vuln_match_reason == "general_cpe")
            continue;
        if (!showSingleVersionVulns && vulns[i].vuln_match_reason == "single_higher_version_cpe")
            continue;

        if (selectedColumns.length < 1 || selectedColumns.includes('cve'))
            vulns_csv += `${escapeCSV(vulns[i]["id"])},`
        if (selectedColumns.length < 1 || selectedColumns.includes('cvss'))
            vulns_csv += `${escapeCSV(vulns[i]["cvss"] + ' (v' + vulns[i]["cvss_ver"] + ')')},`;
        if (selectedColumns.length < 1 || selectedColumns.includes('descr'))
            vulns_csv += `${escapeCSV(vulns[i]["description"])},`;

        if (vulns_csv.length > 0 && (!has_exploits || (selectedColumns.length > 0 && !selectedColumns.includes('expl'))))
            vulns_csv = vulns_csv.slice(0, -1);

        if (has_exploits && vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedColumns.length < 1 || selectedColumns.includes('expl'))) {
            if (onlyShowEDBExploits)
                vulns_csv += `${escapeCSV(reduceToEDBUrls(vulns[i].exploits).join(", "))}`;
            else
                vulns_csv += `${escapeCSV(vulns[i].exploits.join(", "))}`;
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
    if (cpe_parts[4] && cpe_parts[4] != cpe_parts[3]) {
        var append_words = cpe_parts[4].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
        append_words = append_words.replace(/^[\W_]+/, '');
        append_words = append_words.charAt(0).toUpperCase() + append_words.slice(1);
        product_title += append_words;
    }

    if (cpe_parts[5] && cpe_parts[5] != '-' && cpe_parts[5] != '*')
        product_title += cpe_parts[5] + ' ';

    if (cpe_parts[6] && cpe_parts[6] != '-' && cpe_parts[6] != '*')
        product_title += cpe_parts[6] + ' ';

    cpe_parts.slice(7).forEach(cpe_part => {
        if (cpe_part && cpe_part != '-' && cpe_part != '*') {
            var cpe_part = cpe_part[0].toUpperCase() + cpe_part.substring(1);
            cpe_condition += cpe_part.split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
        }
    });

    product_title = product_title.trim();
    cpe_condition = cpe_condition.trim();

    if (cpe_condition)
        return product_type + ': ' + product_title + ' ' + '[' + cpe_condition + ']';

    return product_type + ': ' + product_title
}


function searchVulns(query, url_query, recaptcha_response) {
    var headers = {}
    if (recaptcha_response !== undefined)
        headers = {'Recaptcha-Response': recaptcha_response}

    var apiKey = localStorage.getItem('apiKey');
    if (apiKey !== undefined && apiKey !== null && apiKey)
        headers['API-Key'] = apiKey

    $.get({
        url: "/api/search-vulns",
        headers: headers,
        data: url_query,
        success: function (vulns) {
            var search_display_html = "", related_queries_html = '', queryError = false;
            if (typeof Object.values(vulns)[0] !== "object") {
                search_display_html = `<h5 class="text-error text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                queryError = true;
            }
            else {
                vulns = Object.values(vulns)[0]
                var cpe = vulns['cpe'];
                if (cpe != undefined) {
                    curVulnData = vulns['vulns'];
                    cpe = cpe.split('/')
                    search_display_html = `<div class="row mt-2"><div class="col text-center text-info"><h5 style="font-size: 1.05rem;">${htmlEntities(query)} <span class="nowrap whitespace-nowrap">(${htmlEntities(cpe[0])}`;
                    if (cpe.length > 1) {  // query has equivalent CPEs
                        search_display_html += '<div class="dropdown dropdown-hover dropdown-bottom dropdown-end ml-2"><div class="btn btn-circle btn-outline btn-info btn-xxs"><i class="fa-solid fa-up-right-and-down-left-from-center"></i></div><div class="dropdown-content translate-x-2.5 z-[1] p-3 shadow bg-base-300 rounded-box text-base-content w-fit" onclick="document.activeElement.blur();"><h5 class="font-medium text-left text-sm">Equivalent CPEs that were included into your search: <div class="tooltip tooltip-top text-wrap ml-1" data-tip="Sometimes there are multiple CPEs for one product, e.g. because of a rebranding."><i class="fas fa-info-circle text-content"></i></div></h5><ul tabindex="0" class="list-disc pl-6 mt-1 text-left text-sm font-light">';
                        cpe.shift();  // remove first element, i.e. the primarily matched CPE
                        cpe = cpe.sort();
                        cpe.forEach(function (curCpe) {
                            search_display_html += `<li class="mt-1">${htmlEntities(curCpe)}</li>`;
                        });
                        search_display_html += '</ul></div></div>';
                    }
                    search_display_html += `)</span></h5></div></div>`;
                    curEOLData = {'query': query, 'version_status': vulns.version_status};
                    if (vulns.version_status) {
                        if (vulns.version_status.status == 'eol') {
                            search_display_html += `<div class="row mt-1 mb-3 text-warning text-smxs font-light">${htmlEntities(query)} is end of life. The latest version is ${htmlEntities(vulns.version_status.latest)} (see <a class="link" target="_blank" href="${htmlEntities(vulns.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle" onclick="copyToClipboardEOLProof(this)"><i class="fa-brands fa-markdown"></i></button></span></div>`;
                        }
                        else if (vulns.version_status.status == 'outdated') {
                            search_display_html += `<div class="row mt-1 mb-3 text-warning text-smxs font-light">${htmlEntities(query)} is out of date. The latest version is ${htmlEntities(vulns.version_status.latest)} (see <a class="link" target="_blank" href="${htmlEntities(vulns.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle" onclick="copyToClipboardEOLProof(this)"><i class="fa-brands fa-markdown"></i></button></span></div>`;
                        }
                        else if (vulns.version_status.status == 'current') {
                            search_display_html += `<div class="row mt-1 mb-3 text-success text-smxs font-light">${htmlEntities(query)} is up to date (see <a class="link" target="_blank" href="${htmlEntities(vulns.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle"><i class="fa-brands fa-markdown" onclick="copyToClipboardEOLProof(this)"></i></button></span></div>`;
                        }
                        else if (vulns.version_status.status == 'N/A') {
                            search_display_html += `<div class="row mt-1 mb-3 text-base-content text-smxs font-light">The latest version of ${htmlEntities(query)} is ${htmlEntities(vulns.version_status.latest)} (see <a class="link" target="_blank" href="${htmlEntities(vulns.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle" onclick="copyToClipboardEOLProof(this)"><i class="fa-brands fa-markdown"></i></button></span></div>`;
                        }
                    }
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
                        related_queries_html += `<ul class="list-disc text-left pl-6">`;
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
            errorMsg = htmlEntities(errorMsg);

            if (jXHR["status"] == 403 && errorMsg.toLowerCase().includes("captcha")) {
                errorMsg += ' Set up a key <a class="link" href="/api/setup">here<a>.';
            }

            $("#vulns").html(`<h5 class="text-error w-full text-center">${errorMsg}</h5>`);

            $("#buttonSearchVulns").removeClass("btn-disabled");
            $("#buttonFilterCVEs").removeClass("btn-disabled");
            $("#buttonManageColumns").removeClass("btn-disabled");
            $("#buttonExportResults").removeClass("btn-disabled");
            $("#buttonSearchVulns").html('<i class="fa-solid fa-magnifying-glass"></i> Search Vulns');
            currentlySearchingVulns = false;
        }
    });
}

function searchVulnsAction(actionElement) {
    clearTimeout(doneTypingQueryTimer);

    var query = $('#query').val(), queryEnc;
    if (query === undefined)
        query = '';

    if (actionElement.id.startsWith('cpe-suggestion')) {
        queryEnc = encodeURIComponent($(actionElement).html());
        isGoodCpe = false;
    }
    else {
        queryEnc = encodeURIComponent(query);
    }

    url_query = "query=" + queryEnc;
    new_url = window.location.pathname + '?query=' + queryEnc;

    if (!isGoodCpe) {
        url_query += "&is-good-cpe=false";
        new_url += '&is-good-cpe=false';
    }

    // false is default in backend and filtering is done in frontend
    url_query += "&include-single-version-vulns=true";

    isGoodCpe = true;  // reset for subsequent query that wasn't initiated via URL

    history.pushState({}, null, new_url);  // update URL
    $("#buttonSearchVulns").html('<span class="loading loading-spinner"></span> Searching');
    $("#buttonSearchVulns").addClass("btn-disabled");
    $("#buttonFilterCVEs").addClass("btn-disabled");
    $("#buttonManageColumns").addClass("btn-disabled");
    $("#buttonExportResults").addClass("btn-disabled");
    $('#cpeSuggestions').addClass("hidden");
    $('#cpeSuggestions').html();
    curSelectedCPESuggestion = -1;
    searchIgnoreNextKeyup = true;

    $("#search-display").html("");
    $("#related-queries-display").html("");
    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curSortColIdx = 1;
    curSortColAsc = false;
    curVulnData = {};
    curEOLData = {};

    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(function() {
            grecaptcha.execute().then(function(recaptcha_response) {
                searchVulns(query, url_query, recaptcha_response);
            });
        });
    }
    else {
        searchVulns(query, url_query);
    }
}

function reorderVulns(sortColumnIdx, asc) {
    curSortColIdx = sortColumnIdx;
    curSortColAsc = asc;
    var hasVulns = renderSearchResults(true);
    if (!hasVulns)
        $('#vulns').html(noVulnsFoundHtml);
}

function copyToClipboardEOLProof(clickedButton) {
    // copy Markdown proof to clipboard depending on version status
    var markdownProof = '';
    if (curEOLData.version_status) {
        if (curEOLData.version_status.status == 'eol') {
            markdownProof = `${htmlEntities(curEOLData.query)} is end of life. The latest version is ${htmlEntities(curEOLData.version_status.latest)} (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
        else if (curEOLData.version_status.status == 'outdated') {
            markdownProof = `${htmlEntities(curEOLData.query)} is out of date. The latest version is ${htmlEntities(curEOLData.version_status.latest)} (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
        else if (curEOLData.version_status.status == 'current') {
            markdownProof = `${htmlEntities(curEOLData.query)} is up to date (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
        else if (curEOLData.version_status.status == 'N/A') {
            markdownProof = `The latest version of ${htmlEntities(curEOLData.query)} is ${htmlEntities(curEOLData.version_status.latest)} (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
    }
    navigator.clipboard.writeText(markdownProof);

    // indicate success
    $(clickedButton).removeClass('text-base-content');
    $(clickedButton).addClass('text-success');
    setTimeout(function() {
        $(clickedButton).removeClass('text-success');
        $(clickedButton).addClass('text-base-content');
    }, 1750);
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

function retrieveCPESuggestions(url_query, recaptcha_response) {
    var headers = {}
    if (recaptcha_response !== undefined)
        headers['Recaptcha-Response'] = recaptcha_response

    var apiKey = localStorage.getItem('apiKey');
    if (apiKey !== undefined && apiKey !== null && apiKey)
        headers['API-Key'] = apiKey

    $.get({
        url: "/api/cpe-suggestions",
        data: url_query,
        headers: headers,
        success: function (cpeInfos) {
            if (!Array.isArray(cpeInfos)) {
                console.log(cpeInfos)
                $('#cpeSuggestions').html('<span class="text-error">An error occured, see console</span>');
            }
            else if (cpeInfos.length > 0) {
                var dropdownContent = '<ul class="menu menu-md p-1 bg-base-200 rounded-box">';
                for (var i = 0; i < cpeInfos.length; i++) {
                    dropdownContent += `<li><a class="text-nowrap whitespace-nowrap" id="cpe-suggestion-${i}" onclick="searchVulnsAction(this)">${htmlEntities(cpeInfos[i][0])}</a></li>`;
                }
                dropdownContent += '</ul>';
                $('#cpeSuggestions').html(dropdownContent);
            }
            else {
                $('#cpeSuggestions').html("No results found");
            }
            curSelectedCPESuggestion = -1
            suggestedQueriesJustOpened = true;
            setTimeout(function () {
                suggestedQueriesJustOpened = false;
            }, 400);
            $("#buttonSearchVulns").removeClass("btn-disabled");
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;

            console.log(errorMsg);

            if (jXHR["status"] == 403 && errorMsg.toLowerCase().includes("captcha")) {
                    $('#cpeSuggestions').html('<span class="text-error">No valid API key / CAPTCHA provided. Set up a key <a class="link" onmousedown="location.href = \'/api/setup\'">here<a>.');
            }
            else {
                $('#cpeSuggestions').html('<span class="text-error">' + htmlEntities(errorMsg) + '</span>');
            }

            $("#buttonSearchVulns").removeClass("btn-disabled");
        }
    });
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

    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(function() {
            grecaptcha.execute().then(function(recaptcha_response) {
                retrieveCPESuggestions(url_query, recaptcha_response);
            });
        });
    }
    else {
        retrieveCPESuggestions(url_query);
    }
}

function closeCPESuggestions(event) {
    // Check that new focused element lies without the queryInputConstruct / dropdown
    var newFocusedElement = event.relatedTarget;
    if (newFocusedElement === null || newFocusedElement.closest('#queryInputConstruct') === null) {
        $('#cpeSuggestions').addClass('hidden');
    }
}


/* init */

// enables the user to press return on the query text field to make the query
$("#query").keypress(function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == "13") {
        if (!$("#cpeSuggestions").hasClass("hidden") || !$("#buttonSearchVulns").hasClass("btn-disabled")) {
            var highlightedCPESuggestion = null;
            if ($("#cpeSuggestions").find('ul') != null) {
                highlightedCPESuggestion = $("#cpeSuggestions").find('.my-menu-item-hover');
            }
            if (!highlightedCPESuggestion || curSelectedCPESuggestion == -1)
                $("#buttonSearchVulns").click();
            else
                document.getElementById('cpe-suggestion-' + curSelectedCPESuggestion).click();
        }
    }
});


// check for API key
if (localStorage.getItem('apiKey') !== null)
    document.cookie = 'isAPIKeyConfigured=true; secure; path=/';

// fix dropdown open buttons to close again on click
fixDropdownClicking();

// setup configuration from LocalStorage
setupConfigFromLocalstorage();

// check for existing query in URL and insert its parameters
initQuery();

// register timers and functions for query input field
// on keyup, start the countdown to register finished typing
queryInput.on('keyup', function (event) {
    if (event.keyCode !== undefined) {
        // arrows (up: 38 ; down: 40)
        if ([38, 40].includes(event.keyCode) && !$('#cpeSuggestions').hasClass('hidden') && $("#cpeSuggestions").find('ul') != null) {
            if (curSelectedCPESuggestion > -1)
                $('#cpe-suggestion-' + curSelectedCPESuggestion).removeClass('my-menu-item-hover');

            if (event.keyCode == 38)
                curSelectedCPESuggestion--;
            else if (event.keyCode == 40)
                curSelectedCPESuggestion++;

            // enforce lower and upper bounds
            curSelectedCPESuggestion = Math.max(-1, curSelectedCPESuggestion);
            curSelectedCPESuggestion = Math.min(curSelectedCPESuggestion, $("#cpeSuggestions").find('ul').children('li').length - 1);

            if (curSelectedCPESuggestion > -1)
                $('#cpe-suggestion-' + curSelectedCPESuggestion).addClass('my-menu-item-hover');

            event.preventDefault();  // prevent jumping of cursor to start or end
        }
        // any key except CTRL, OPTION, CMD/SUPER/Windows
        else if (![13, 17, 18, 91, 229].includes(event.keyCode)) {
            clearTimeout(doneTypingQueryTimer);
            if (!searchIgnoreNextKeyup)
                doneTypingQueryTimer = setTimeout(doneTypingQuery, doneTypingQueryInterval);
            searchIgnoreNextKeyup = false;
        }
    }
});

// on keydown, clear the typing countdown and hide dropdown
queryInput.on('keydown', function (event) {
    if (event.keyCode !== undefined) {
        if ([38, 40].includes(event.keyCode) && !$('#cpeSuggestions').hasClass('hidden') && $("#cpeSuggestions").find('ul') != null) {
            event.preventDefault();  // prevent jumping of cursor to start or end
        }
        // any key except CTRL, OPTION, CMD/SUPER/Windows
        else if(![13, 17, 18, 37, 39, 91, 229].includes(event.keyCode)) {
            clearTimeout(doneTypingQueryTimer);
            $('#cpeSuggestions').addClass("hidden");
            $('#cpeSuggestions').html();
        }
    }
});

// focus on query input field at the beginning
window.onload = function () {
    queryInput.focus();
}
