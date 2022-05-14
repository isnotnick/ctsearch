/*
	pagination
	icons/favicon
	permanent day-mode (ie dont take from system?)
	don't use CDNs like CF (exlcude bulk?)
	js front-end with loader?

	filter search input to only reg-domain and search on that - maybe extract, search, search again?
	timeout/connection retries

	max-certid works instant on 'certs' table but not sans?
	search on FQDN - how?
	limits?

	was there a way to see how many results first?

	'no results' if empty

	graceful errors

	ajax

	single-page tool
	checks/dropdowns for additional functionality
	log searches - where? (anonymised IPs?)

	icons for CAs - maybe cert types?

	links to crt.sh (censys?)

	SANs in CSV - and hover-over in table
	replace the square-brackets in SAN output if present?


	CSV to XLSX

*/

package main

import (
	"bytes"
	"database/sql"
	"embed"
	"errors"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/ClickHouse/clickhouse-go/v2"
)

//	Struct definitions
type PerCAResult struct {
	CertCount int 			`db:"CertCount"`
	CAIssuerDN string 		`db:"CAIssuerDN"`
	CACertID int 			`db:"CACertID"`
}

type CertResult struct {
	CACertID int 			`db:"CACertID"`
	CertID int 				`db:"CertID"`
	CommonName string  		`db:"CommonName"`
	SANCount int 			`db:"SANCount"`
	NotBefore string 		`db:"NotBefore"`
	NotAfter string 		`db:"NotAfter"`
	CertType string 		`db:"CertType"`
	ValType string 			`db:"ValType"`
	CABrand string 			`db:"CABrand"`
}

type CertExport struct {
	CACertID int 			`db:"CACertID"`
	CertID int 				`db:"CertID"`
	CommonName string  		`db:"CommonName"`
	SANEntries string  		`db:"SANEntries"`
	SANCount int 			`db:"SANCount"`
	SerialNumber string 	`db:"SerialNumber"`
	NotBefore string 		`db:"NotBefore"`
	NotAfter string 		`db:"NotAfter"`
	CertType string 		`db:"CertType"`
	ValType string 			`db:"ValType"`
	CABrand string 			`db:"CABrand"`
}

var dbPG *sqlx.DB

//go:embed templates/*
var f embed.FS

func main() {
	router := gin.Default()
	//	No proxies today
	router.SetTrustedProxies(nil)

	gin.SetMode(gin.DebugMode)

	//	Load HTML templates
	templateEmbed := template.Must(template.New("").ParseFS(f, "templates/*.html"))
	router.SetHTMLTemplate(templateEmbed)

	// Index route
	router.GET("/", ctPage)

	// Static routes for 'assets'
	router.StaticFile("/favicon.ico", "./assets/favicon.ico")
	router.StaticFile("/gridjs-umd-5.02.js", "./assets/js/gridjs-umd-5.02.js")
	router.StaticFile("/mermaid.gridjs.css", "./assets/css/mermaid.gridjs.css")
	router.StaticFile("/ctlogsearch.css", "./assets/css/ctlogsearch.css")
	router.Static("/assets", "./assets")

	// Page routes


	// API routes
	v1 := router.Group("/api/v1")
	{
		v1.GET("/domain/allvalid/:domainName", fetchValidCertsJSON)
		v1.GET("/domainperca/allvalid/:domainName", fetchValidCertsJSONPerCA)
		v1.GET("/domain/allvalid/exportcsv/:domainName", fetchValidCertsCSV)
		// get all with expired
		// get everything (expired? unexpired?) as CSV/XLSX?
		// get individual
		// get sumamry data JSON for charting
	}

	dbConnection()

	router.Run("0.0.0.0:8080")
}

//	DB Connection
//	Add retry logic?
func dbConnection() {

	connStr := "clickhouse://default:d4t4b453@185.193.17.195:9440/ctlog?secure=true&skip_verify=true&dial_timeout=2000ms&max_execution_time=120"

	var err error
	dbPG, err = sqlx.Connect("clickhouse", connStr)
	if err != nil {
		panic(err)
	}
	errPing := dbPG.Ping()
	if errPing != nil {
		panic(err)
	}
}


//	Main index page
func ctPage(c *gin.Context) {
	c.HTML(http.StatusOK, "ctsearch.html",
		gin.H{
			"title": "Certificate Transparency Log Search",
		},
	)
}

/*
func domainSearch(c *gin.Context) {
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	caResults := []*PerCAResult{}

	domainQuery := c.Query("domainName")

	certResults, err := queryCertsByDomain(domainQuery, true)
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
		return
	}

	//	This query gets all certificates matching the provided FQDN, unexpires, de-duplicates and then groups by how many are issued per CA (ie per unique issuer DN)
	query := `SELECT
					cas.caid AS CACertID,
					concat(JSONExtractString (cas.subjectdn, '2-5-4-3'), ' [', cas.caowner, ']') AS CAIssuerDN,
					count(DISTINCT certs.certid) AS CertCount
				FROM
					certs
					INNER JOIN cas ON certs.issuerid = cas.caid
				WHERE
					certid IN(
						SELECT
							certid FROM sans
						WHERE
							regdomain = $1)
					AND notafter > toUnixTimestamp (now())
				GROUP BY
					CAIssuerDN, CACertID
				ORDER BY
					CertCount DESC;`

	err = dbPG.Select(&caResults, query, domainQuery)
	if err != nil {
		fmt.Println("Error with grouped-by-ca query: ", err)
	}

	resultsSize := len(certResults)


	c.HTML(http.StatusOK, "newresults.html",
		gin.H{
			"PerCAResults": caResults,
			"CertResultsList": certResults,
			"PageTitle":  "CT Search Results",
			"DomainName": domainQuery,
			"ResultSize": resultsSize,
		},
	)
}


func domainSearch(c *gin.Context) {
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	caResults := []*PerCAResult{}
	certResults := []*CertResult{}

	domainQuery := c.Query("domainName")

	//	This query gets all certificates matching the provided FQDN, unexpires, de-duplicates and then groups by how many are issued per CA (ie per unique issuer DN)
	query := `SELECT
					cas.caid AS CACertID,
					concat(JSONExtractString (cas.subjectdn, '2-5-4-3'), ' [', cas.caowner, ']') AS CAIssuerDN,
					count(DISTINCT certs.certid) AS CertCount
				FROM
					certs
					INNER JOIN cas ON certs.issuerid = cas.caid
				WHERE
					certid IN(
						SELECT
							certid FROM sans
						WHERE
							regdomain = $1)
					AND notafter > toUnixTimestamp (now())
				GROUP BY
					CAIssuerDN, CACertID
				ORDER BY
					CertCount DESC;`

	query2 := `SELECT
					cas.caid AS CACertID,
					COALESCE(JSONExtractString (certs.subjectdn, '2-5-4-3'), 'No CN') AS CommonName,
					certs.sancount AS SANCount,
					certs.certid AS CertID,
					FROM_UNIXTIME(certs.notbefore) AS NotBefore,
					FROM_UNIXTIME(certs.notafter) AS NotAfter,
					certs.certtype AS CertType,
					certs.validationtype AS ValType,
					COALESCE(certs.cabrand, 'Unknown') AS CABrand
				FROM
					certs
					INNER JOIN cas ON certs.issuerid = cas.caid
				WHERE
					certid IN(
						SELECT
							certid FROM sans
						WHERE
							regdomain = $1)
					AND notafter > toUnixTimestamp (now())
				ORDER BY
					NotBefore ASC;`

	err := dbPG.Select(&caResults, query, domainQuery)
	if err != nil {
		fmt.Println("Error with grouped-by-ca query: ", err)
	}

	err = dbPG.Select(&certResults, query2, domainQuery)
	if err != nil {
		fmt.Println("Error with per-cert-list query: ", err)
	}


	resultsSize := len(certResults)

	// Output the results of per-CA, and then the page will ajax-load pages of the individual results
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
	}

	c.HTML(http.StatusOK, "mainresults.html",
		gin.H{
			"PerCAResults": caResults,
			"CertResultsList": certResults,
			"PageTitle":  "CT Search Results",
			"DomainName": domainQuery,
			"ResultSize": resultsSize,
		},
	)
}


func domainSearchPerCA(c *gin.Context) {
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	certResults := []*CertResult{}

	domainQuery := c.Param("domainName")
	caID := c.Param("caid")
	var caName string

	query := `SELECT
				cas.caid AS CACertID,
				COALESCE(JSONExtractString (certs.subjectdn, '2-5-4-3'), 'No CN') AS CommonName,
				certs.sancount AS SANCount,
				certs.certid AS CertID,
				FROM_UNIXTIME(certs.notbefore) AS NotBefore,
				FROM_UNIXTIME(certs.notafter) AS NotAfter,
				certs.certtype AS CertType,
				certs.validationtype AS ValType
			FROM
				certs
				INNER JOIN cas ON certs.issuerid = cas.caid
			WHERE
				certid IN(
					SELECT
						certid FROM sans
					WHERE
						regdomain = $1)
				--	AND notbefore > toUnixTimestamp ('2022-01-01 00:00:00')
				AND notafter > toUnixTimestamp (now())
				AND cas.caid = $2
			ORDER BY
				NotBefore ASC;`

	query2 := `SELECT
					cas.subjectdn AS ISSUER_NAME
				FROM
					cas
				WHERE
					cas.caid = $1;`
	
	err := dbPG.Select(&certResults, query, domainQuery, caID)
	if err != nil {
		fmt.Println("Error with per-ca-cert-list query: ", err)
	}

	err = dbPG.Get(&caName, query2, caID)
	if err != nil {
		fmt.Println("Error with ca name query: ", err)
	}

	resultsSize := len(certResults)

	// Output the results of per-CA, and then the page will ajax-load pages of the individual results
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
	}

	c.HTML(http.StatusOK, "percaresults.html",
		gin.H{
			"CertResultsList": certResults,
			"PageTitle":  "CT Search Results",
			"DomainName": domainQuery,
			"ResultSize": resultsSize,
			"CAName": ReplaceWithOIDNames(caName),
		},
	)
}
*/

func fetchValidCertsJSONPerCA(c *gin.Context) {
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	domainQuery := c.Param("domainName")

	//fmt.Println("Looking up: ", domainQuery)

	certResults, err := queryCertsByDomainPerCA(domainQuery, true)
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs: "+ err.Error(),
			},
		)
		return
	}

	c.JSON(http.StatusOK, certResults)
}

func fetchValidCertsJSON(c *gin.Context) {
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	domainQuery := c.Param("domainName")

	//fmt.Println("Looking up: ", domainQuery)

	certResults, err := queryCertsByDomain(domainQuery, true)
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs: "+ err.Error(),
			},
		)
		return
	}

	c.JSON(http.StatusOK, certResults)
}

func fetchValidCertsCSV(c *gin.Context) {
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	/*query := `SELECT
				cas.caid AS CACertID,
				COALESCE(JSONExtractString (certs.subjectdn, '2-5-4-3'), 'No CN') AS CommonName,
				certs.sancount AS SANCount,
				certs.certid AS CertID,
				FROM_UNIXTIME(certs.notbefore) AS NotBefore,
				FROM_UNIXTIME(certs.notafter) AS NotAfter,
				certs.certtype AS CertType,
				certs.validationtype AS ValType,
				COALESCE(certs.cabrand, 'Unknown') AS CABrand
			FROM
				certs
				INNER JOIN cas ON certs.issuerid = cas.caid
			WHERE
				certid IN(
					SELECT
						certid FROM sans
					WHERE
						regdomain = $1)
				AND notafter > toUnixTimestamp (now())
			ORDER BY
				NotBefore ASC;`
	*/

	tempTable1 := randomString(8)

	tempTable2 := randomString(8)

	query1 := "CREATE TABLE " + tempTable1 + " ENGINE = Memory AS SELECT * FROM sans WHERE regdomain = $1 ORDER BY certid ASC;"

	query2 := "CREATE TABLE " + tempTable2 + " ENGINE = Memory AS SELECT * FROM certs WHERE certid IN (SELECT certid FROM " + tempTable1 + " ORDER BY certid) ORDER BY notbefore ASC;"

	query4 := "DROP TABLE " + tempTable1

	query5 := "DROP TABLE " + tempTable2
	
	query3 := `SELECT
		tmpCERTS.issuerid AS CACertID,
		COALESCE(JSONExtractString (tmpCERTS.subjectdn, '2-5-4-3'), 'No CN') AS CommonName,
		arrayStringConcat(groupArray (san), ',') AS SANEntries,
		tmpCERTS.sancount AS SANCount,
		tmpCERTS.serialnumber AS SerialNumber,
		tmpCERTS.certid AS CertID,
		FROM_UNIXTIME(tmpCERTS.notbefore) AS NotBefore,
		FROM_UNIXTIME(tmpCERTS.notafter) AS NotAfter,
		tmpCERTS.certtype AS CertType,
		tmpCERTS.validationtype AS ValType,
		COALESCE(tmpCERTS.cabrand, 'Unknown') AS CABrand
	FROM
		tmpSANS
		RIGHT OUTER JOIN tmpCERTS ON tmpSANS.certid = tmpCERTS.certid
	INNER JOIN cas ON tmpCERTS.issuerid = cas.caid
	WHERE
		tmpCERTS.notafter > toUnixTimestamp (now())
	GROUP BY
		CACertID,
		CommonName,
		SANCount,
		SerialNumber,
		CertID,
		NotBefore,
		NotAfter,
		CertType,
		ValType,
		CABrand;`

	finalQuery1 := strings.Replace(query3, "tmpSANS", tempTable1, -1)
	query := strings.Replace(finalQuery1, "tmpCERTS", tempTable2, -1)

	//fmt.Println("query: ", query)

	_, err := dbPG.Exec(query1, c.Param("domainName"))
	if err != nil {
		fmt.Println("Error (q1) querying all certs for CSV: ", err)
	}
	_, err = dbPG.Exec(query2)
	if err != nil {
		fmt.Println("Error (q2) querying all certs for CSV: ", err)
	}

	certResults := []*CertExport{}
	
	err = dbPG.Select(&certResults, query)
	if err != nil {
		fmt.Println("Error (big) querying all certs for CSV: ", err)
	}

	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
	}

	_, err = dbPG.Exec(query4)
	if err != nil {
		fmt.Println("Error (q4) querying all certs for CSV: ", err)
	}
	_, err = dbPG.Exec(query5)
	if err != nil {
		fmt.Println("Error (q5) querying all certs for CSV: ", err)
	}

	b := &bytes.Buffer{}
	w := csv.NewWriter(b)

	if err = w.Write([]string{"Certificate ID", "Issuer ID", "Common Name", "SAN Entries", "SAN Count", "SerialNumber", "NotBefore", "NotAfter", "Certificate Type", "Validation Type", "CA Brand"}); err != nil {
		panic(err)
	}

	for _, thisCertificate := range certResults {
		var csvLine []string
		csvLine = append(csvLine, "https://crt.sh/?id="+strconv.Itoa(thisCertificate.CertID))
		csvLine = append(csvLine, "https://crt.sh/?caid="+strconv.Itoa(thisCertificate.CACertID))
		csvLine = append(csvLine, thisCertificate.CommonName)
		csvLine = append(csvLine, thisCertificate.SANEntries)
		csvLine = append(csvLine, strconv.Itoa(thisCertificate.SANCount))
		csvLine = append(csvLine, thisCertificate.SerialNumber)
		csvLine = append(csvLine, thisCertificate.NotBefore)
		csvLine = append(csvLine, thisCertificate.NotAfter)
		csvLine = append(csvLine, thisCertificate.CertType)
		csvLine = append(csvLine, thisCertificate.ValType)
		csvLine = append(csvLine, thisCertificate.CABrand)

		if err := w.Write(csvLine); err != nil {
			fmt.Println("Error writing line to csv:", err)
		}
	}
	w.Flush()

	if err := w.Error(); err != nil {
		fmt.Println(err)
	}
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename=export-"+ c.Param("domainName") +".csv")
	c.Data(http.StatusOK, "text/csv", b.Bytes())



	//c.IndentedJSON(http.StatusOK, certResults)
	/*
	type CertExport struct {
	CAID int 				`json:"caid"`
	CertID int 				`json:"certid"`
	CommonName string  		`json:"commonname"`
	SANEntries string  		`json:"sanentries"`
	SANCount int 			`json:"sancount"`
	NotBefore string 		`json:"notbefore"`
	NotAfter string 		`json:"notafter"`
	CertType string 		`json:"certtype"`
	ValType string 			`json:"valtype"`
	CABrand string 			`json:"cabrand"`
	}*/
}

//	Get certs by domain
//	Bool toggle for expired/only currently-valid
//	How to deal with searching for FQDN? Only that specifically? (Extract registerable domain first, search, get all subdomains?)
//	How to deal with large results?
func queryCertsByDomain(domainName string, onlyValid bool) ([]*CertResult, error) {
	certResults := []*CertResult{}

	//	Ping DB, if fails - try a reconnect
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	//	Extract registerable domain from domainName input

	//	This query fetches all unexpired (at time of query) certs, de-duplicated and with simplified output fields
	query := `SELECT
				cas.caid AS CACertID,
				COALESCE(JSONExtractString (certs.subjectdn, '2-5-4-3'), 'No CN') AS CommonName,
				certs.sancount AS SANCount,
				certs.certid AS CertID,
				FROM_UNIXTIME(certs.notbefore) AS NotBefore,
				FROM_UNIXTIME(certs.notafter) AS NotAfter,
				certs.certtype AS CertType,
				certs.validationtype AS ValType,
				COALESCE(certs.cabrand, 'Unknown') AS CABrand
			FROM
				certs
				INNER JOIN cas ON certs.issuerid = cas.caid
			WHERE
				certid IN(
					SELECT
						certid FROM sans
					WHERE
						regdomain = $1)
				AND notafter > toUnixTimestamp (now())
			ORDER BY
				NotBefore ASC;`
	if !onlyValid {
		query = `SELECT
				cas.caid AS CACertID,
				COALESCE(JSONExtractString (certs.subjectdn, '2-5-4-3'), 'No CN') AS CommonName,
				certs.sancount AS SANCount,
				certs.certid AS CertID,
				FROM_UNIXTIME(certs.notbefore) AS NotBefore,
				FROM_UNIXTIME(certs.notafter) AS NotAfter,
				certs.certtype AS CertType,
				certs.validationtype AS ValType,
				COALESCE(certs.cabrand, 'Unknown') AS CABrand
			FROM
				certs
				INNER JOIN cas ON certs.issuerid = cas.caid
			WHERE
				certid IN(
					SELECT
						certid FROM sans
					WHERE
						regdomain = $1)
			ORDER BY
				NotBefore ASC;`
	}

	if domainName == "" {
		return certResults, errors.New("No domain to query!")
	}
	
	err := dbPG.Select(&certResults, query, domainName)

	if err != nil {
		return certResults, err
	}

	return certResults, nil
}

//	Get certs by domain - per CA
func queryCertsByDomainPerCA(domainName string, onlyValid bool) ([]*PerCAResult, error) {
	certResultsPerCA := []*PerCAResult{}

	//	Ping DB, if fails - try a reconnect
	errPing := dbPG.Ping()
	if errPing != nil {
		dbConnection()
	}

	//	This query gets all certificates matching the provided FQDN, unexpires, de-duplicates and then groups by how many are issued per CA (ie per unique issuer DN)
	query := `SELECT
					cas.caid AS CACertID,
					concat(JSONExtractString (cas.subjectdn, '2-5-4-3'), ' [', cas.caowner, ']') AS CAIssuerDN,
					count(DISTINCT certs.certid) AS CertCount
				FROM
					certs
					INNER JOIN cas ON certs.issuerid = cas.caid
				WHERE
					certid IN(
						SELECT
							certid FROM sans
						WHERE
							regdomain = $1)
					AND notafter > toUnixTimestamp (now())
				GROUP BY
					CAIssuerDN, CACertID
				ORDER BY
					CertCount DESC;`
	if !onlyValid {
		query = `SELECT
					cas.caid AS CACertID,
					concat(JSONExtractString (cas.subjectdn, '2-5-4-3'), ' [', cas.caowner, ']') AS CAIssuerDN,
					count(DISTINCT certs.certid) AS CertCount
				FROM
					certs
					INNER JOIN cas ON certs.issuerid = cas.caid
				WHERE
					certid IN(
						SELECT
							certid FROM sans
						WHERE
							regdomain = $1)
				GROUP BY
					CAIssuerDN, CACertID
				ORDER BY
					CertCount DESC;`
	}

	if domainName == "" {
		return certResultsPerCA, errors.New("No domain to query!")
	}
	
	err := dbPG.Select(&certResultsPerCA, query, domainName)

	if err != nil {
		return certResultsPerCA, err
	}

	return certResultsPerCA, nil
}


//	Helper functions

func jsonify(rows *sql.Rows) ([]string) {
	columns, err := rows.Columns()
	if err != nil {
		panic(err.Error())
	}

	values := make([]interface{}, len(columns))

	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	c := 0
	results := make(map[string]interface{})
	data := []string{}

	for rows.Next() {
		if c > 0 {
			data = append(data, ",")
		}

		err = rows.Scan(scanArgs...)
		if err != nil {
			panic(err.Error())
		}

		for i, value := range values {
			switch value.(type) {
				case nil:
					results[columns[i]] = nil

				case []byte:
					s := string(value.([]byte))
					x, err := strconv.Atoi(s)

					if err != nil {
						results[columns[i]] = s
					} else {
						results[columns[i]] = x
					}


				default:
					results[columns[i]] = value
			}
		}

		b, _ := json.Marshal(results)
		data = append(data, strings.TrimSpace(string(b)))
		c++
	}

	return data
}

func PrettyPrint(v interface{}) (err error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
			fmt.Println(string(b))
	}
	return
}

func ReplaceWithOIDNames(inputString string) string {
	inputString = strings.Replace(inputString, "1-2-840-113549-1-9-1", "E", -1)
	inputString = strings.Replace(inputString, "1-2-840-113549-1-9-2", "unstructuredName", -1)
	inputString = strings.Replace(inputString, "1-3-6-1-4-1-311-60-2-1-1", "jurisdictionL", -1)
	inputString = strings.Replace(inputString, "1-3-6-1-4-1-311-60-2-1-2", "jurisdictionST", -1)
	inputString = strings.Replace(inputString, "1-3-6-1-4-1-311-60-2-1-3", "jurisdictionC", -1)
	inputString = strings.Replace(inputString, "2-5-4-10", "O", -1)
	inputString = strings.Replace(inputString, "2-5-4-11", "OU", -1)
	inputString = strings.Replace(inputString, "2-5-4-12", "title", -1)
	inputString = strings.Replace(inputString, "2-5-4-13", "description", -1)
	inputString = strings.Replace(inputString, "2-5-4-15", "businessCategory", -1)
	inputString = strings.Replace(inputString, "2-5-4-17", "postalCode", -1)
	inputString = strings.Replace(inputString, "2-5-4-18", "POBox", -1)
	inputString = strings.Replace(inputString, "2-5-4-20", "tel", -1)
	inputString = strings.Replace(inputString, "2-5-4-3", "CN", -1)
	inputString = strings.Replace(inputString, "2-5-4-4", "SN", -1)
	inputString = strings.Replace(inputString, "2-5-4-41", "name", -1)
	inputString = strings.Replace(inputString, "2-5-4-42", "GN", -1)
	inputString = strings.Replace(inputString, "2-5-4-46", "dnQualifier", -1)
	inputString = strings.Replace(inputString, "2-5-4-5", "serial", -1)
	inputString = strings.Replace(inputString, "2-5-4-6", "C", -1)
	inputString = strings.Replace(inputString, "2-5-4-7", "L", -1)
	inputString = strings.Replace(inputString, "2-5-4-8", "ST", -1)
	inputString = strings.Replace(inputString, "2-5-4-9", "street", -1)
	inputString = strings.Replace(inputString, "2-5-4-97", "organizationIdentifier", -1)
	return inputString
}

func randomString(n int) string {
	var chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321")
	str := make([]rune, n)
	for i := range str {
		str[i] = chars[rand.Intn(len(chars))]
	}
	return string(str)
}